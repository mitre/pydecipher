# -*- coding: utf-8 -*-
"""Code related to the unfreezing of Python contents within zip archives.

Many Python freezing applications will include code (user code, standard library
code, third party modules, etc) inside a zipfile distributed in the overlay of
the interpreter binary or as a separate file entirely.
"""

import io
import os
import pathlib
import zipfile
import zlib
from pathlib import Path
from typing import Any, BinaryIO, List, Union

import pydecipher
from pydecipher import logger, utils

__all__ = ["ZipFile"]


@pydecipher.register
class ZipFile:
    """The artifact class representing a zip file.

    Zip files of compiled Python files are often found alongside frozen interpreter
    binaries, or attached to the binaries overlay. They typically contain more than
    just the compiled Python standard library files needed to run the interpreter
    and developer's code, including things like the Microsoft C++ Visual Runtime,
    application manifests, and miscellaneous resources.

    Attributes
    ----------
    archive_path : pathlib.Path, optional
        If this artifact comes from a file on disk, this is the path to that file.
    archive_contents : bytes
        The contents of the archive read into memory.
    output_dir : os.PathLike
        Where any output extracted from this artifact should get dumped.
    kwargs: Any
        Any keyword arguments needed for the parsing of this artifact, or for
        parsing nested artifacts.
    """

    archive_path: pathlib.Path
    archive_contents: bytes
    output_dir: pathlib.Path
    kwargs: Any

    def __init__(
        self,
        zip_path_or_bytes: Union[str, pathlib.Path, BinaryIO],
        output_dir: pathlib.Path = None,
        **kwargs,
    ) -> None:
        """Construct a zip file artifact.

        Parameters
        ----------
        zip_path_or_bytes : Union[str, os.PathLike, BinaryIO]
            The path to the zip file, or a bytes-like object of a zip file in memory.
        output_dir : os.PathLike, optional
            Where any output extracted from this artifact should get dumped.
        **kwargs
            Any keyword arguments needed for the parsing of this artifact, or for
            parsing nested artifacts.

        Raises
        ------
        TypeError
            Will raise a TypeError if the zip_path_or_bytes item is not a zip archive.
        """
        if isinstance(zip_path_or_bytes, str):
            zip_path_or_bytes: Path = Path(zip_path_or_bytes)
        if isinstance(zip_path_or_bytes, Path):
            utils.check_read_access(zip_path_or_bytes)
            self.archive_path = zip_path_or_bytes
            input_file: BinaryIO
            with self.archive_path.open("rb") as input_file:
                self.archive_contents = input_file.read()
        if isinstance(zip_path_or_bytes, io.BufferedIOBase):
            self.archive_contents = zip_path_or_bytes.read()

        if output_dir:
            self.output_dir = output_dir
        else:
            if hasattr(self, "archive_path"):
                self.output_dir = self.archive_path.parent / utils.slugify(self.archive_path.name + "_output")
            else:
                self.output_dir = Path.cwd()

        self.kwargs = kwargs
        utils.check_write_access(self.output_dir.parent)
        if not self.validate_zip_archive():
            raise TypeError("[!] This is not a zip archive.")

    def validate_zip_archive(self) -> bool:
        """Check if the contents of the class object is a valid zip archive.

        Returns
        -------
        bool
            True if this is a valid zip archive, False if not.
        """
        fake_file: io.BytesIO = io.BytesIO(self.archive_contents)
        # The zipfile.is_zipfile function will return true if the PK\05\06 magic is found ANYWHERE in the file.
        # This causes issues for zipfile.pyc, a bytecode file found in frozen interpreters, as well as PEs with zip
        # files in the overlay. The workaround here is twofold - first, check if you can successfully create the
        # zipfile python object, which would catch instances where files simply have the PK magic and are not actually
        # compressed zip archives. Second, check that the magic bytes appear in the beginning of the file.
        first_two_bytes: bytes = fake_file.read(2)
        fake_file.seek(0)
        if zipfile.is_zipfile(fake_file) and first_two_bytes == b"PK":
            try:
                _ = zipfile.PyZipFile(fake_file, "r", zipfile.ZIP_DEFLATED)
            except Exception:
                pass
            else:
                return True
        return False

    def unpack(self) -> None:
        """Recursively search this artifact for frozen Python artifacts."""
        zip_bytes: io.BytesIO
        with io.BytesIO(self.archive_contents) as zip_bytes:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            try:
                f: zipfile.PyZipFile = zipfile.PyZipFile(zip_bytes, "r", zipfile.ZIP_DEFLATED)
                f.extractall(self.output_dir)
            except (zipfile.BadZipfile, zlib.error):
                pass
            else:
                seen_errors: List[str] = []
                list_of_files: List[os.PathLike] = []
                for (dirpath, dirnames, filenames) in os.walk(self.output_dir):
                    for filename in filenames:
                        full_path: pathlib.Path = Path(dirpath).joinpath(filename)
                        list_of_files.append(full_path)

                logger.info(f"[*] Unpacking {len(list_of_files)} files found in this zip file...")
                fp: pathlib.Path
                for fp in list_of_files:
                    try:
                        pydecipher.unpack(fp, **self.kwargs)
                    except RuntimeError as e:
                        if str(e) and str(e) not in seen_errors:
                            seen_errors.append(str(e))

                if seen_errors:
                    logger.error(
                        f"[!] The following {len(seen_errors)} errors were encountered during the unpacking"
                        " of this zip file."
                    )
                    err: str
                    for err in seen_errors:
                        logger.error(err)
