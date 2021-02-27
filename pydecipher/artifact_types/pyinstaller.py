# -*- coding: utf-8 -*-
import enum
import io
import os
import pathlib
import struct
import zlib
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from typing import Dict
from typing import List
from typing import Tuple
from typing import Union
from uuid import uuid4 as uniquename

import xdis
from Crypto.Cipher import AES
from xdis.magics import magic2int
from xdis.disasm import disassemble_file

import pydecipher
from pydecipher import bytecode
from pydecipher import logger
from pydecipher import utils


@pydecipher.register
class CArchive:
    PYINST20_COOKIE_SIZE: int = 24  # For PyInstaller 2.0
    PYINST21_COOKIE_SIZE: int = 24 + 64  # For PyInstaller 2.1+
    MAGIC: bytes = b"MEI\014\013\012\013\016"  # Magic number which identifies PyInstaller CArchive
    magic_index: int
    archive_path: pathlib.Path
    archive_contents: bytes
    pyinstaller_version: float
    python_version: float
    toc: List["CTOCEntry"] = []
    output_dir: Path
    potential_zlib_archive_passwords: List[str] = []

    class ArchiveItem(enum.Enum):
        """The different types of entries in a CArchive.

        Look here for more info: https://github.com/pyinstaller/pyinstaller/blob/1844d69f5aa1d64d3feca912ed1698664a3faf3e/bootloader/src/pyi_archive.h#L18
        """

        BINARY = "b"  # binary
        DEPENDENCY = "d"  # runtime option
        PYZ = "z"  # zlib (pyz) - frozen Python code
        ZIPFILE = "Z"  # zlib (pyz) - frozen Python code
        PYPACKAGE = "M"  # Python package (__init__.py)
        PYMODULE = "m"  # Python module
        PYSOURCE = "s"  # Python script (v3)
        DATA = "x"  # data
        RUNTIME_OPTION = "o"  # runtime option

        @staticmethod
        def from_str(value):
            try:
                return CArchive.ArchiveItem(value)
            except ValueError:
                logger.warning(f"[!] Unknown item type found in archive with type code letter '{value}'")
                return CArchive.ArchiveItem.DATA

    class CTOCEntry:
        entry_offset: int
        compressed_data_size: int
        uncompressed_data_size: int
        compression_flag: bool
        type_code: "CArchive.ArchiveItem"
        name: str
        ENTRYSTRUCT = "!iiiiBB"
        ENTRYLEN = struct.calcsize(ENTRYSTRUCT)

        def __init__(
            self,
            entry_offset: int,
            compressed_data_size: int,
            uncompressed_data_size: int,
            compression_flag: bool,
            type_code: str,
            name: str,
        ):
            self.entry_offset = entry_offset
            self.compressed_data_size = compressed_data_size
            self.uncompressed_data_size = uncompressed_data_size
            self.compression_flag = compression_flag
            self.type_code = CArchive.ArchiveItem.from_str(type_code)
            self.name = name

    def __init__(
        self,
        carchive_path_or_bytes: Union[str, os.PathLike, BinaryIO],
        output_dir: os.PathLike = None,
        **kwargs,
    ):
        if isinstance(carchive_path_or_bytes, str):
            carchive_path_or_bytes: Path = Path(carchive_path_or_bytes)
        if isinstance(carchive_path_or_bytes, Path):
            if not carchive_path_or_bytes.exists():
                msg = f"[!] Could not find the provided path: {str(carchive_path_or_bytes)}."
                raise FileNotFoundError(msg)
            if not os.access(carchive_path_or_bytes, os.R_OK):
                msg = f"[!] Lacking read permissions on: {str(carchive_path_or_bytes)}."
                raise PermissionError(msg)
            self.archive_path = carchive_path_or_bytes
            with self.archive_path.open("rb") as input_file:
                self.archive_contents = input_file.read()
        if isinstance(carchive_path_or_bytes, io.BufferedIOBase):
            self.archive_contents = carchive_path_or_bytes.read()

        if output_dir:
            self.output_dir = output_dir
        else:
            if hasattr(self, "archive_path"):
                self.output_dir = self.archive_path.parent / utils.slugify(self.archive_path.name + "_output")
            else:
                self.output_dir = Path.cwd()
        if not os.access(self.output_dir.parent, os.W_OK):
            msg = f"[!] Cannot write output directory to dir: {str(self.output_dir)}."
            raise PermissionError(msg)

        if not self.validate_pyinstaller_carchive():
            raise TypeError(
                "[!] This is not a PyInstaller CArchive (or is an archive of an unsupported PyInstaller version"
            )

    def validate_pyinstaller_carchive(self):
        self.magic_index = self.archive_contents.find(self.MAGIC)
        cookie_size = len(self.archive_contents) - self.magic_index
        if self.magic_index > 0:
            if cookie_size == self.PYINST20_COOKIE_SIZE:
                self.pyinstaller_version = 2.0
                logger.debug("[*] PyInstaller version: 2.0")
                return True
            elif cookie_size == self.PYINST21_COOKIE_SIZE:
                self.pyinstaller_version = 2.1  # or greater
                return True
                logger.debug("[*] PyInstaller version: 2.1")
            else:
                logger.debug(
                    f"[!] PyInstaller cookie size is {cookie_size}, which does not correspond to a known "
                    "version of PyInstaller."
                )
                if cookie_size < 100:
                    # Some valid cookies were seen with size 94
                    self.pyinstaller_version = "unknown"
                    return True
                else:
                    return False
        else:
            logger.debug("[!] Could not find PyInstaller magic within this archive.")
        return False

    def parse_toc(self):
        # Read CArchive cookie
        if self.pyinstaller_version == 2.0 or self.pyinstaller_version == "unknown":
            try:
                (magic, self.length_of_package, self.toc_offset, self.toc_size, self.python_version,) = struct.unpack(
                    "!8siiii",
                    self.archive_contents[self.magic_index : self.magic_index + self.PYINST20_COOKIE_SIZE],
                )
            except:
                pass
            else:
                self.pyinstaller_version = 2.0
        if self.pyinstaller_version == 2.1 or self.pyinstaller_version == "unknown":
            try:
                (
                    magic,
                    self.length_of_package,
                    self.toc_offset,
                    self.toc_size,
                    self.python_version,
                    self.python_dynamic_lib,
                ) = struct.unpack(
                    "!8siiii64s",
                    self.archive_contents[self.magic_index : self.magic_index + self.PYINST21_COOKIE_SIZE],
                )
            except:
                pass
            else:
                self.pyinstaller_version = 2.1
                if self.python_dynamic_lib:
                    self.python_dynamic_lib = self.python_dynamic_lib.decode("ascii").rstrip("\x00")

        if self.pyinstaller_version == "unknown":
            logger.warning("[!] Could not parse CArchive because PyInstaller version is unknown.")
            return

        self.python_version = float(self.python_version) / 10
        logger.info(f"[*] This CArchive was built with Python {self.python_version}")
        logger.debug(f"[*] CArchive Package Size: {self.length_of_package}")
        logger.debug(f"[*] CArchive Python Version: {self.python_version}")
        if self.pyinstaller_version == 2.1:
            logger.debug(f"[*] CArchive Python Dynamic Library Name: {self.python_dynamic_lib}")

        self.toc = []
        toc_bytes = self.archive_contents[self.toc_offset : self.toc_offset + self.toc_size]
        while toc_bytes:
            (entry_size,) = struct.unpack("!i", toc_bytes[0:4])
            name_length = entry_size - self.CTOCEntry.ENTRYLEN
            (
                entry_offset,
                compressed_data_size,
                uncompressed_data_size,
                compression_flag,
                type_code,
                name,
            ) = struct.unpack(f"!iiiBB{name_length}s", toc_bytes[4:entry_size])

            name = name.decode("utf-8").rstrip("\0")
            if name == "":
                name = str(uniquename())
                logger.debug(f"[!] Warning: Found an unnamed file in CArchive. Using random name {name}")

            type_code = chr(type_code)
            self.toc.append(
                self.CTOCEntry(
                    entry_offset,
                    compressed_data_size,
                    uncompressed_data_size,
                    compression_flag,
                    type_code,
                    name,
                )
            )

            toc_bytes = toc_bytes[entry_size:]
        logger.debug(f"[*] Found {len(self.toc)} entries in this PyInstaller CArchive")

    def extract_files(self):
        magic_nums: set = set()
        decompression_errors = 0
        successfully_extracted = 0
        entry: CTOCEntry
        for entry in self.toc:
            data = self.archive_contents[entry.entry_offset : entry.entry_offset + entry.compressed_data_size]

            if entry.compression_flag:
                try:
                    data = zlib.decompress(data)
                except zlib.error as e:
                    decompression_errors += 1
                    logger.debug(f"[!] PyInstaller CArchive decompression failed with error: {e}")
                    continue
                else:
                    if len(data) != entry.uncompressed_data_size:
                        logger.warning(
                            f"[!] {entry.name} entry in CArchive listed its uncompressed data size as"
                            f" {entry.uncompressed_data_size}, however in actuality, uncompressed to be {len(data)}"
                            " bytes. This may be a sign that the CArchive was manually altered."
                        )

            if "\\" in entry.name:
                tmp: PureWindowsPath = pathlib.PureWindowsPath(entry.name)
            else:
                tmp: Path = Path(entry.name)
            file_path = pathlib.Path(self.output_dir).joinpath(tmp)
            if len(file_path.parents) > 1:  # every path has '.' as a parent
                file_path.parent.mkdir(parents=True, exist_ok=True)

            if entry.type_code == self.ArchiveItem.PYSOURCE:
                if ord(data[:1]) == ord(xdis.marsh.TYPE_CODE) or ord(data[:1]) == (
                    ord(xdis.marsh.TYPE_CODE) | xdis.unmarshal.FLAG_REF
                ):
                    file_path = file_path.parent / (file_path.name + ".pyc")
                    if len(magic_nums) > 1:
                        magic_num = next(iter(magic_nums))
                        logger.warning(
                            "[!] More than one magic number found within this CArchive. Using magic number"
                            f" {magic_num}, but also found numbers: {magic_nums}"
                        )
                    elif len(magic_nums) == 0:
                        logger.warning(f"[!] No magic numbers have been found yet, queueing this file for later.")
                        # TODO: add this file to a do-later list, when you know the magic num  #TODO does this actually happen? dig deeper...
                        pass
                    data = pydecipher.bytecode.create_pyc_header(next(iter(magic_nums))) + data
                else:
                    file_path = file_path.parent / (file_path.name + ".py")
                if "pyi" not in entry.name:
                    logger.info(f"[!] Potential entrypoint found at script {entry.name}.py")
            elif entry.type_code == self.ArchiveItem.PYMODULE:
                magic_bytes = data[:4]  # Python magic value
                magic_nums.add(magic2int(magic_bytes))
                file_path = file_path.parent / (file_path.name + ".pyc")

            if entry.type_code != self.ArchiveItem.RUNTIME_OPTION:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                with file_path.open(mode="wb") as f:
                    f.write(data)
                    successfully_extracted += 1

            if entry.type_code in (self.ArchiveItem.PYZ, self.ArchiveItem.ZIPFILE):
                output_dir_name = (
                    str(file_path.parent.joinpath(utils.slugify(file_path.name.split(".")[0]))) + "_output"
                )
                pydecipher.unpack(file_path, output_dir=output_dir_name)

        if decompression_errors:
            logger.debug(f"[!] Failed to write {decompression_errors} files due to decompression errors.")
        if successfully_extracted:
            logger.info(f"[+] Successfully extracted {successfully_extracted} files from this CArchive.")

    def unpack(self) -> None:
        self.parse_toc()
        if self.toc:
            self.extract_files()


@pydecipher.register
class ZlibArchive:
    """
    Pyinstaller ZlibArchive (.pyz)
    """

    potential_keys = List[str]
    encryption_key: str = ""
    encrypted: bool = False
    archive_path: Path
    archive_contents: bytes
    magic_int: int
    toc: Dict[str, Tuple]
    compilation_time: datetime

    class ArchiveItem(enum.Enum):
        """The different types of entries in a ZlibArchive.

        Look here for more info: https://github.com/pyinstaller/pyinstaller/blob/1844d69f5aa1d64d3feca912ed1698664a3faf3e/PyInstaller/loader/pyimod02_archive.py#L41
        """

        MODULE = 0
        PKG = 1
        DATA = 2

        @staticmethod
        def from_int(value):
            try:
                return ZlibArchive.ArchiveItem(value)
            except ValueError:
                logger.warning(f"[!] Unknown item type found in ZlibArchive with type code number '{value}'")
                return ZlibArchive.ArchiveItem.DATA

    class ZTOCEntry:
        name: str
        type_code: "ZlibArchive.ArchiveItem"
        position: int
        compressed_data_size: int

        def __init__(self, name: str, type_code: str, position: int, compressed_data_size: int):
            """
            :type position: Offset in the archive where the member starts
            :type compressed_data_size: Size of compressed member data, if compressed. Otherwise, zero.
            :type uncompressed_data_size: Size of uncompressed member data
            :type compressed_flag: Bool indicating where member is compressed
            :type type_code: Single char indicating type of
            """
            self.name = name
            self.type_code = type_code
            self.position = position
            self.compressed_data_size = compressed_data_size

    def __init__(
        self,
        zlibarchive_path_or_bytes: Union[str, os.PathLike, BinaryIO],
        output_dir: os.PathLike = None,
        **kwargs,
    ):
        if isinstance(zlibarchive_path_or_bytes, str):
            zlibarchive_path_or_bytes: Path = Path(zlibarchive_path_or_bytes)
        if isinstance(zlibarchive_path_or_bytes, Path):
            if not zlibarchive_path_or_bytes.exists():
                msg = f"[!] Could not find the provided path: {str(zlibarchive_path_or_bytes)}."
                raise FileNotFoundError(msg)
            if not os.access(zlibarchive_path_or_bytes, os.R_OK):
                msg = f"[!] Lacking read permissions on: {str(zlibarchive_path_or_bytes)}."
                raise PermissionError(msg)
            self.archive_path = zlibarchive_path_or_bytes
            with self.archive_path.open("rb") as input_file:
                self.archive_contents = input_file.read()
        if isinstance(zlibarchive_path_or_bytes, io.BufferedIOBase):
            self.archive_contents = zlibarchive_path_or_bytes.read()

        if output_dir:
            self.output_dir = output_dir
        else:
            if hasattr(self, "file_path"):
                self.output_dir = self.file_path.parent / utils.slugify(self.file_path.name + "_output")
            else:
                self.output_dir = Path.cwd()
        if not os.access(self.output_dir.parent, os.W_OK):
            msg = f"[!] Cannot write output directory to dir: {str(self.output_dir)}."
            raise PermissionError(msg)
        # if not self.output_dir.exists():
        #     self.output_dir.mkdir(parents=True)

        if not self.validate_zlibarchive():
            raise TypeError(
                "[!] This is not a PyInstaller ZlibArchive (or is an archive of an unsupported PyInstaller version"
            )

    def validate_zlibarchive(self):
        if self.archive_contents[:4] == b"PYZ\0" and CArchive.MAGIC not in self.archive_contents:
            return True
        else:
            return False

    def check_for_password_file(self):
        self.potential_keys = []
        if hasattr(self, "archive_path"):
            dir_of_pyz = self.archive_path.parent
        else:
            dir_of_pyz = Path.cwd()

        key_file = dir_of_pyz / "pyimod00_crypto_key.pyc"
        if key_file.exists():
            self.encrypted = True
            logger.debug(f"[+] Found ZlibArchive encryption key file at path {key_file}")
            crypto_key_filename: str  # full path of
            try:
                (
                    crypto_key_filename,
                    crypto_key_co,
                    crypto_key_python_version,
                    crypto_key_compilation_timestamp,
                    crypto_key_magic_int,
                    crypto_key_is_pypy,
                    crypto_key_source_size,
                    crypto_key_sip_hash,
                ) = disassemble_file(str(key_file), outstream=open(os.devnull, "w"))
            except Exception as e:
                logger.warning(f"[!] Could not disassemble file {key_file}. Received error: {e}")
            else:
                self.compilation_time = datetime.fromtimestamp(crypto_key_compilation_timestamp)
                for const_string in crypto_key_co.co_consts:
                    if const_string and len(const_string) == 16:
                        self.potential_keys.append(const_string)
            # If we couldn't decompile the file to see the consts, lets just search the raw bytes of the file
            # for the password
            if not self.potential_keys:
                with key_file.open("rb") as file_ptr:
                    file_strings = utils.parse_for_strings(file_ptr.read())
                s: str
                for s in file_strings:
                    if len(s) >= 16 and "pyimod00_crypto_key" not in s:
                        while len(s) >= 16:
                            self.potential_keys.append(s[0:16])
                            s = s[1:]

            logger.info(f"[*] Found these potential PyInstaller PYZ Archive encryption keys: {self.potential_keys}")

            if not self.potential_keys:
                logger.error(f"[*] Encryption key file detected, however no password was able to be retrieved.")

    def parse_toc(self) -> None:
        self.magic_int = magic2int(self.archive_contents[4:8])
        (toc_position,) = struct.unpack("!i", self.archive_contents[8:12])
        self.toc = xdis.unmarshal.load_code(
            self.archive_contents[toc_position:], self.magic_int
        )  # TODO wrap this in try block?
        logger.debug(f"[*] Found {len(self.toc)} entries in this PYZ archive")

        # From PyInstaller 3.1+ toc is a list of tuples
        if isinstance(self.toc, list):
            self.toc = dict(self.toc)

    def decrypt_file(self, data) -> Union[bytes, None]:
        CRYPT_BLOCK_SIZE = 16
        initialization_vector = data[:CRYPT_BLOCK_SIZE]

        if not self.encryption_key:
            while self.potential_keys:
                encryption_key = self.potential_keys.pop(0)
                try:
                    cipher: AES.AESCipher = AES.new(encryption_key.encode(), AES.MODE_CFB, initialization_vector)
                    decrypted_data = cipher.decrypt(data[CRYPT_BLOCK_SIZE:])  # will silently fail if password is wrong
                    _ = zlib.decompress(decrypted_data)  # ensures the password is correct
                except zlib.error as e:
                    logger.debug(f"[!] Decryption of .pyc failed with password {encryption_key}. Discarding key.")
                else:
                    self.encryption_key = encryption_key
                    logger.debug(f"[!] Verified ZlibArchive password is {self.encryption_key}.")
                    return decrypted_data
        else:
            try:
                cipher: AES.AESCipher = AES.new(self.encryption_key.encode(), AES.MODE_CFB, initialization_vector)
                return cipher.decrypt(data[CRYPT_BLOCK_SIZE:])
            except zlib.error as e:
                logger.error(f"[!] Failed to decrypt .pyc with error: {e}")
                return None

    def extract_files(self) -> None:
        decompression_errors = 0
        successfully_extracted = 0
        for key in self.toc.keys():
            (type_code, position, compressed_data_size) = self.toc[key]
            if not hasattr(self, "compilation_time"):
                timestamp = None
            else:
                timestamp = self.compilation_time
            header_bytes = pydecipher.bytecode.create_pyc_header(self.magic_int, compilation_ts=timestamp, file_size=0)

            compressed_data = self.archive_contents[position : position + compressed_data_size]
            if self.encrypted:
                compressed_data = self.decrypt_file(compressed_data)
            if compressed_data is None:
                # decrypt_file returns None on failure
                decompression_errors += 1
                continue

            try:
                uncompressed_data = zlib.decompress(compressed_data)
            except zlib.error as e:
                decompression_errors += 1
                logger.debug(f"[!] PYZ zlib decompression failed with error: {e}")
            else:
                pyc_file = self.output_dir / str(key + ".pyc")
                self.output_dir.mkdir(parents=True, exist_ok=True)
                with pyc_file.open("wb") as pyc_file_ptr:
                    pyc_file_ptr.write(header_bytes + uncompressed_data)
                successfully_extracted += 1

        if decompression_errors:
            logger.debug(f"[!] Failed to write {decompression_errors} files due to decompression errors.")
        if successfully_extracted:
            logger.info(f"[+] Successfully extracted {successfully_extracted} files from this ZlibArchive.")

    def unpack(self) -> None:
        self.check_for_password_file()
        self.parse_toc()
        if self.toc:
            self.extract_files()
