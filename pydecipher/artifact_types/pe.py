# -*- coding: utf-8 -*-
"""Code for the handling of Portable Executable files within pydecipher's pipeline.

pydecipher extracts several items from PE files. First, it will search for the
PYTHONSCRIPT resource, which is an artifact from Py2Exe-frozen binaries that contains
a marshalled list of code objects related to the initialization of the user code.
Second, if the PE has extra data appended to it (the overlay), pydecipher will dump
this extra data to a separate file within the output directory for further inspection.
"""
import abc
import io
import json
import os
import pprint
import re
import pathlib
from typing import Any, BinaryIO, Dict, List, Tuple, Union

import asn1crypto
import pefile
import signify
from asn1crypto import pem
from signify.authenticode import AuthenticodeSignedData

import pydecipher
from pydecipher import logger, utils


@pydecipher.register
class PortableExecutable(metaclass=abc.ABCMeta):
    """The artifact class representing a Portable Executable Windows binary.

    Much of the functionality is just an augmentation of the pefile library
    to aid in analysis of python packaged artifacts.

    Attributes
    ----------
    file_path : pathlib.Path, optional
        If this artifact comes from a file on disk, this is the path to that file.
    file_contents : bytes
        The contents of the file read into memory.
    output_dir : os.PathLike
        Where any output extracted from this artifact should get dumped.
    python_version : str
        The version of Python used to create this frozen artifact.
    overlay: bytes
        The overlay of the PE (the data that is appended to the binary).
    pe : pefile.PE
        The pefile library PE object for this file.
    version_info : Dict[bytes, bytes]
        The version info resource of this executable stored as key:value pairs.
    certificates_dumped : bool
        Whether or not the certificates (if they exist in the PE) have been
        dumped to the output directory on disk.
    INTERESTING_RESOURCES : List[str]
        String-matching patterns for resources that should be dumped to disk if
        found within a PE.
    kwargs : Any
        Any keyword arguments needed for the parsing of this artifact, or for
        parsing nested artifacts.

    Raises
    ------
    TypeError
        Will raise a TypeError if the file_path_or_bytes item is not a recognizable PE object.
    """

    output_dir: pathlib.Path
    python_version: str = ""
    pe: pefile.PE
    file_contents: bytes
    file_path: pathlib.Path
    kwargs: Any
    overlay: bytes
    version_info: Dict[bytes, bytes] = {}
    certificates_dumped: bool = False
    INTERESTING_RESOURCES: List[str] = [
        "pythonscript",
        r"python.*\.dll",
    ]  # case-insensitive patterns for resources that should be dumped/unpacked

    def __init__(
        self,
        pe_path_or_bytes: Union[str, os.PathLike, BinaryIO],
        output_dir: os.PathLike = None,
        **kwargs,
    ) -> None:
        if isinstance(pe_path_or_bytes, str):
            pe_path_or_bytes: pathlib.Path = pathlib.Path(pe_path_or_bytes)
        if isinstance(pe_path_or_bytes, pathlib.Path):
            utils.check_read_access(pe_path_or_bytes)
            self.file_path = pe_path_or_bytes
            with self.file_path.open("rb") as input_file:
                self.file_contents = input_file.read()
        if isinstance(pe_path_or_bytes, io.BufferedIOBase):
            self.file_contents = pe_path_or_bytes.read()

        try:
            self.pe = pefile.PE(data=self.file_contents)
        except pefile.PEFormatError as e:
            raise TypeError(e)

        if output_dir:
            self.output_dir = output_dir
        else:
            if hasattr(self, "file_path"):
                self.output_dir = self.file_path.parent / utils.slugify(self.file_path.name + "_output")
            else:
                self.output_dir = pathlib.Path.cwd()
        utils.check_write_access(self.output_dir)
        self.kwargs = kwargs

    def dump_resource(self, resource_name: str) -> pathlib.Path:
        """Dump the specified resource to the output directory on disk.

        Parameters
        ----------
        resource_name
            The name of the resource within the PE's resources to extract.

        Returns
        -------
        pathlib.Path
            The path to the dumped resource.
        """
        entry: pefile.ResourceDirEntryData
        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.name.string.decode() == resource_name:
                rva: int = entry.directory.entries[0].directory.entries[0].data.struct.OffsetToData
                size: int = entry.directory.entries[0].directory.entries[0].data.struct.Size

                self.output_dir.mkdir(parents=True, exist_ok=True)
                resource_dump: pathlib.Path = self.output_dir / resource_name
                outfile_ptr: BinaryIO
                with resource_dump.open("wb") as outfile_ptr:
                    outfile_ptr.write(self.pe.get_data(rva, size))
                logger.info(f"[+] Successfully dumped PE resource {resource_name} to disk at {self.output_dir}")
                return resource_dump

    def load_version_info(self, quiet: bool = False) -> None:
        """Extract the VersionInfo dictionary from the pefile.PE object.

        If pydecipher is running in anything but 'quiet' mode, it will print
        the version info to the log. Additionally, it will search for Python
        version strings within the version info.

        Parameters
        ----------
        quiet : bool, optional
            Whether or not to print the version info dictionary to the log.
        """
        if not hasattr(self.pe, "FileInfo"):
            return
        structure: pefile.Structure
        for structure in self.pe.FileInfo:
            sub_structure: pefile.Structure
            for sub_structure in structure:
                if sub_structure.Key != b"StringFileInfo":
                    continue
                if hasattr(sub_structure, "StringTable"):
                    string_table: pefile.Structure
                    for string_table in sub_structure.StringTable:
                        if string_table.entries:
                            self.version_info = {
                                x.decode("utf-8"): y.decode("utf-8") for x, y in string_table.entries.items()
                            }
        formatted_version_info: Dict[str, str] = json.dumps(self.version_info, indent=4, separators=(",", ": "))
        if not quiet:
            logger.debug(f"[*] This PE had the following VersionInfo resource: {formatted_version_info}")

        if "python" in str(self.version_info).lower():
            if "FileVersion" in self.version_info:
                self.python_version = self.version_info["FileVersion"]
            if "ProductVersion" in self.version_info:
                if self.python_version and len(self.python_version) < len(self.version_info["ProductVersion"]):
                    # assume longer string means more detailed version info (we'd rather know it was 2.7.14 vs just 2.7)
                    self.python_version = self.version_info["ProductVersion"]

    def dump_certificates(self, output_dir: pathlib.Path = None) -> None:
        """Dump Authenticode certificates from the PE's certificate attribute table.

        Parameters
        ----------
        output_dir: pathlib.Path, optional
            An optional alternative output directory to dump the certificates, besides
            the class's output directory.
        """
        certificate_table_entry: pefile.Structure = None
        if hasattr(self.pe, "OPTIONAL_HEADER") and hasattr(self.pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            idx: int
            for idx in range(len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
                directory: pefile.Structure = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
                if directory.name == "IMAGE_DIRECTORY_ENTRY_SECURITY" and directory.Size:
                    logger.debug("[*] This PE has a certificate table.")
                    certificate_table_entry = directory
                    break

        if certificate_table_entry is None:
            return

        if output_dir is None:
            certificate_extraction_dir: pathlib.Path = self.output_dir.joinpath("Authenticode_Certificates")
        else:
            certificate_extraction_dir: pathlib.Path = output_dir
        certificate_extraction_dir.mkdir(parents=True, exist_ok=True)

        certificate_table_data: bytes = self.pe.__data__[certificate_table_entry.VirtualAddress :]
        while certificate_table_data:
            # https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#the-attribute-certificate-table-image-only
            cert_length: int = int.from_bytes(certificate_table_data[0:4], byteorder="little")
            cert_version: bytes = certificate_table_data[4:6]  # noqa
            cert_type = certificate_table_data[6:8]  # noqa
            cert: bytes = certificate_table_data[8 : 8 + cert_length]
            certificate_table_data: bytes = certificate_table_data[8 + cert_length :]

            # Extract all the X509 certificates from the PKCS#7 structure
            authenticode_structure: signify.authenticode.AuthenticodeSignedData = AuthenticodeSignedData.from_envelope(
                cert
            )
            cert_obj: signify.certificates.Certificate
            for cert_obj in authenticode_structure.certificates:
                cert_name_obj: asn1crypto.x509.Name = cert_obj.to_asn1crypto.subject
                preferred_name_fields: List[str] = [
                    "organizational_unit_name",
                    "organization_name",
                    "common_name",
                ]
                name_selected: bool = False
                preferred_field_name: str
                for preferred_field_name in preferred_name_fields:
                    name_tuple: Tuple[str, str]
                    for name_tuple in cert_name_obj.native.items():
                        field: str = name_tuple[0]
                        value: str = name_tuple[1]
                        if field == preferred_field_name:
                            name_selected = True
                            cert_name: str = value
                            break
                    if name_selected:
                        break
                if not name_selected:
                    cert_name: str = f"{len(os.listdir(certificate_extraction_dir))}"
                cert_name: str = utils.slugify(cert_name, allow_unicode=True) + ".pem"

                logger.debug(f"[+] Extracting Authenticode certificate {cert_name}.")
                f: BinaryIO
                with certificate_extraction_dir.joinpath(cert_name).open("wb") as f:
                    der_bytes: bytes = cert_obj.to_asn1crypto.dump()
                    pem_bytes: bytes = pem.armor("CERTIFICATE", der_bytes)
                    f.write(pem_bytes)
        self.certificates_dumped = True

    def dump_overlay(self) -> pathlib.Path:
        """
        Check to see if this binary has data appended, and if so, dump it for further analysis.

        python's pefile library puts the certificate table in the overlay section even
        though its not really traditional overlay data.

        Relevant links:
        https://github.com/erocarrera/pefile/issues/104#issuecomment-429037686
        https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
        https://blog.barthe.ph/2009/02/22/change-signed-executable/

        Returns
        -------
        pathlib.Path
            The path to the dumped overlay on disk.
        """
        certificate_table_entry: pefile.Structure = None
        if hasattr(self.pe, "OPTIONAL_HEADER") and hasattr(self.pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            idx: int
            for idx in range(len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
                directory: pefile.Structure = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
                if directory.name == "IMAGE_DIRECTORY_ENTRY_SECURITY" and directory.Size:
                    certificate_table_entry = directory
                    break

        # Get overlay data, excluding certificate table if its there
        if certificate_table_entry:
            overlay_start: int = self.pe.get_overlay_data_start_offset()
            certificate_start: int = certificate_table_entry.VirtualAddress
            self.overlay = self.pe.__data__[overlay_start:certificate_start]
        else:
            self.overlay = self.pe.get_overlay()

        if self.overlay:
            overlay_path: pathlib.Path = self.output_dir.joinpath("overlay_data")
            self.output_dir.mkdir(parents=True, exist_ok=True)
            overlay_file_ptr: BinaryIO
            with overlay_path.open("wb") as overlay_file_ptr:
                overlay_file_ptr.write(self.overlay)
            logger.info(f"[+] Dumped this PE's overlay data to {overlay_path.relative_to(self.output_dir.parent)}")
            return overlay_path

    def unpack(self) -> None:
        """Dump any interesting aspects of this PE for further investigation.

        This will log the PEs version info resource for manual inspection,
        dump any Authenticode certificates, and look for frozen Python artifacts
        within the PE's resources and overlay.
        """
        self.load_version_info()
        self.dump_certificates()

        unpack_me: List[pathlib.Path] = []
        overlay_path: pathlib.Path = self.dump_overlay()
        if overlay_path:
            unpack_me.append(overlay_path)

        version_strings: List[str] = utils.parse_for_version_strings(self.file_contents)
        if version_strings:
            logger.debug(
                "[*] Found the following strings (and their surrounding bytes, for context) in this PE, which may "
                "indicate the version of Python used to freeze the executable: \n"
                f"{pprint.pformat(version_strings, width=120)}"
            )

        pythonscript_idx: int = None
        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            entry: pefile.ResourceDirEntryData
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.name is None:
                    continue
                resource_name: str = entry.name.string.decode()
                if any([True for pattern in self.INTERESTING_RESOURCES if re.match(pattern, resource_name, re.I)]):
                    resource_path: pathlib.Path = self.dump_resource(resource_name)
                    if resource_name == "PYTHONSCRIPT":
                        pythonscript_idx = len(unpack_me)
                    unpack_me.append(resource_path)

        if pythonscript_idx:
            # We want to unpack Py2Exe PYTHONSCRIPT last to give it highest chance of successfully determining version.
            unpack_me.append(unpack_me.pop(pythonscript_idx))

        artifact_path: pathlib.Path
        for artifact_path in unpack_me:
            output_dir_name: str = utils.slugify(str(artifact_path.name) + "_output")
            pydecipher.unpack(
                artifact_path,
                output_dir=self.output_dir.joinpath(output_dir_name),
                **self.kwargs,
            )
