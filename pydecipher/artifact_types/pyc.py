# -*- coding: utf-8 -*-
"""Code for the handling of Python bytecode files within pydecipher's pipeline.

Individual bytecode files can be obfuscated in a variety of ways. This class
will check for and correct files that have performed the following obfuscations:

    1. Removal of entire header
    2. Incorrect magic bytes (or missing magic bytes)

If you pass in bytes to instantiate this class, and then call unpack, it will
write the bytecode file to disk within the provided output directory.
"""
import io
import pathlib
import struct
import tempfile
from shutil import copyfile
from typing import Any, BinaryIO, List, Union

from xdis.magics import by_magic

import pydecipher
from pydecipher import bytecode, logger, utils

__all__ = ["Pyc"]


@pydecipher.register
class Pyc:
    """The artifact class representing a compiled Python file (.pyc or .pyo).

    Consists of a variable-sized header followed by a marshalled code object.
    This class can reverse some basic obfuscation regarding the removal or
    tampering with the header and magic bytes.

    Attributes
    ----------
    file_path : pathlib.Path, optional
        If this artifact comes from a file on disk, this is the path to that file.
    file_contents : bytes
        The contents of the file read into memory.
    output_dir : os.PathLike
        Where any output extracted from this artifact should get dumped.
    magic_num : int
        Magic number/bytes of the file (first 2, unsigned little endian integer)
    kwargs : Any
        Any keyword arguments needed for the parsing of this artifact, or for
        parsing nested artifacts.

    Raises
    ------
    TypeError
        Will raise a TypeError if the file_path_or_bytes item is not a compiled Python file.
    RuntimeError
        Will raise a RuntimeError if the version-hint provided doesn't correspond
        with a known/supported version. Supported versions are determined by xdis.
    """

    file_path: pathlib.Path
    file_contents: bytes
    output_dir: pathlib.Path
    kwargs: Any
    magic_num: int
    MARSHALLED_CODE_OBJECT_LEADING_BYTES: List[bytes] = [
        b"c\x00\x00\x00\x00\x00\x00\x00",
        b"\xe3\x00\x00\x00\x00\x00\x00\x00",
    ]

    def __init__(
        self,
        file_path_or_bytes: Union[str, pathlib.Path, BinaryIO],
        output_dir: pathlib.Path = None,
        **kwargs,
    ) -> None:
        if isinstance(file_path_or_bytes, str):
            file_path_or_bytes: pathlib.Path = pathlib.Path(file_path_or_bytes)
        if isinstance(file_path_or_bytes, pathlib.Path):
            utils.check_read_access(file_path_or_bytes)
            self.file_path = file_path_or_bytes
            input_file: BinaryIO
            with self.file_path.open("rb") as input_file:
                self.file_contents = input_file.read()
        if isinstance(file_path_or_bytes, io.BufferedIOBase):
            self.file_contents = file_path_or_bytes.read()

        if output_dir:
            self.output_dir = output_dir
        else:
            if hasattr(self, "file_path"):
                self.output_dir = self.file_path.parent / utils.slugify(self.file_path.name + "_output")
            else:
                self.output_dir = pathlib.Path.cwd()
        utils.check_write_access(self.output_dir)

        if not self.validate_pyc_file():
            raise TypeError("[!] This is not a compiled Python file.")
        self.version_hint = kwargs.get("version_hint", None)
        if self.version_hint:
            try:
                self.magic_num = bytecode.version_str_to_magic_num_int(self.version_hint)
            except Exception:
                raise RuntimeError(
                    f"Failed to produce magic number from version hint {self.version_hint}. Please try a different"
                    " version."
                )

    @staticmethod
    def is_headerless(first_eight_bytes: bytes):
        """Check whether the given bytes match the beginning of a Code object.

        Parameters
        ----------
        first_eight_bytes: bytes
            The first eight bytes of a pyc file.

        Returns
        -------
        bool
            True if this pyc lacks a proper header, False if not.
        """
        # First 8 bytes of a marshalled, standard/non-obfuscated code object
        return any(True for p in Pyc.MARSHALLED_CODE_OBJECT_LEADING_BYTES if first_eight_bytes.startswith(p))

    def validate_pyc_file(self) -> bool:
        """Check if the contents of the class object is a valid zip archive.

        Returns
        -------
        bool
           True if this is a valid zip archive, False if not.
        """
        first_24_bytes: bytes = self.file_contents[0 : min(24, len(self.file_contents))]
        if any(True for p in Pyc.MARSHALLED_CODE_OBJECT_LEADING_BYTES if p in first_24_bytes):
            return True
        return False

    @staticmethod
    def check_and_fix_pyc(
        pyc_file: pathlib.Path, provided_version: str = None
    ) -> Union[None, tempfile.NamedTemporaryFile]:
        """Fix a given pyc file so it can be properly disassembled by xdis.

        This function combats the following common obfuscations that may be
        applied to pyc files that would prevent them from easily being disassembled

            1. Missing the header entirely
            2. Missing only the magic bytes
            3. Magic bytes are there, but they don't match a known version
            4. Filename doesn't end in .pyc

        Parameters
        ----------
        pyc_file: pathlib.Path
            The path to the pyc file
        provided_version: str, optional
            The version of the Python that compiled the pyc, if known.

        Raises
        ------
        RuntimeError
            The pyc file is malformed and couldn't be corrected, likely due to
            a version not being given.

        Returns
        -------
        Union[None, tempfile.NamedTemporaryFile]
            If the pyc file is fine as is, this function returns None. If it
            needs to be fixed in some way, the temporary file object
            with the fixes is returned.
        """
        corrected_file_contents: bytes = b""
        all_bytes: bytes = b""
        utils.check_read_access(pyc_file)
        infile: BinaryIO
        with pyc_file.open("rb") as infile:
            first_24_bytes: bytes = infile.read(min(24, pyc_file.stat().st_size))
            infile.seek(0)
            all_bytes = infile.read()

        if not any(True for p in Pyc.MARSHALLED_CODE_OBJECT_LEADING_BYTES if p in first_24_bytes):
            raise RuntimeError(f"This file {str(pyc_file)} isn't pyc file!")

        if provided_version:
            correct_magic_num = bytecode.version_str_to_magic_num_int(provided_version)
            header = bytecode.create_pyc_header(correct_magic_num)
        if Pyc.is_headerless(first_24_bytes[:8]):
            # Is this pyc completely missing a header?
            if provided_version:
                corrected_file_contents = header
                corrected_file_contents += all_bytes
            else:
                logger.error(
                    "[!] The pyc file provided does not have a header. For remap to decompile this, please provide a"
                    " version with the --version flag"
                )
                raise RuntimeError

        elif first_24_bytes[0:4] not in by_magic:
            # Does have a header of sorts, but can't recognize magic numbers.
            # We'll need a version from the user to proceed
            if not provided_version:
                logger.error(
                    "[!] This version has a header, but we can't recognize the magic number"
                    f" {struct.unpack('<H', first_24_bytes[0:2])[0]}. No version was provided to fix the header."
                )
                raise RuntimeError
            else:
                logger.debug(
                    "[*] This version has a header, but we can't recognize the magic number"
                    f" {struct.unpack('<H', first_24_bytes[0:2])[0]}. Using magic num {correct_magic_num} (from"
                    f" provided version {provided_version}) to fix the header."
                )
            code_object_begin_index: int = -1
            pattern: bytes
            for pattern in Pyc.MARSHALLED_CODE_OBJECT_LEADING_BYTES:
                if pattern in all_bytes:
                    code_object_begin_index = all_bytes.index(pattern)
                    break
            corrected_file_contents: bytes = header
            corrected_file_contents += all_bytes[code_object_begin_index:]

        bytes_to_write_out: bytes = b""
        if corrected_file_contents:
            bytes_to_write_out = corrected_file_contents
        elif pyc_file.suffix != ".pyc":
            # There was nothing to correct except the filename, so we just duplicate the file.
            bytes_to_write_out = all_bytes
        else:
            # There was nothing to do with this pyc file. It is seemingly valid.
            return

        temp_file: tempfile.NamedTemporaryFile = tempfile.NamedTemporaryFile(suffix=".pyc")
        pyc_fixed_file: pathlib.Path = pathlib.Path(temp_file.name)
        outfile: BinaryIO
        with pyc_fixed_file.open("wb") as outfile:
            outfile.write(bytes_to_write_out)
        return temp_file

    def unpack(self):
        """Validate as best as possible that this is a well-formed compiled Python file.

        If any obfuscations are detected, we will write a new, corrected file to disk. Does
        not overwrite the original file.
        """
        if not hasattr(self, "file_path"):
            temp_file: tempfile.NamedTemporaryFile = tempfile.NamedTemporaryFile(suffix=".pyc")
            pyc_file: pathlib.Path = pathlib.Path(temp_file.name)
            with pyc_file.open("wb") as outfile:
                outfile.write(self.file_contents)

            # The file was passed in as bytes.
            counter: int = 0
            new_filename_prefix = "pyc_"
            while True:
                new_filepath = self.output_dir.joinpath(f"{new_filename_prefix}{counter}.pyc")
                if not new_filepath.exists():
                    break
                counter += 1
            new_filename: pathlib.Path = new_filepath
        else:
            pyc_file = self.file_path
            new_filename: pathlib.Path = self.file_path.with_suffix(".corrected.pyc")

        if fixed_pyc_tempfile := self.check_and_fix_pyc(pyc_file, provided_version=self.version_hint):
            logger.info(f"[+] Writing fixed pyc file {new_filename.name} to {new_filename.parent}")
            copyfile(fixed_pyc_tempfile.name, new_filename)
