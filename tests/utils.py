# -*- coding: utf-8 -*-
"""Utilities for pydecipher's testing functions."""
import dataclasses
import hashlib
import inspect
import pathlib
import shutil
from types import ModuleType
from typing import Any, BinaryIO, NamedTuple, Union

import pydecipher

all = [
    "PYD_TEST_DATA_DIR",
    "Py2ExeTestParameters",
    "PyInstallerTestParameters",
    "RemapTestParameters",
    "ZipTestParameters",
    "set_up_tmp_dir",
    "sha256_file",
]

PYD_TEST_DATA_DIR: pathlib.Path = pydecipher.PYD_ROOT_DIR / "tests" / "test_data"


@dataclasses.dataclass
class Py2ExeTestParameters:
    """Py2Exe PE parameters for pytest's parameterized testing.

    Attributes
    ----------
    python_version : float
        The version of Python used in test_file.
    test_file : str
        The path to the test file on disk, relative to the tests/test_data dir.
    file_sha256 : str
        The SHA256 digest of test_file.
    main_code_filename : str
        The name of the Python file entrypoint within the frozen sample that will be unpacked.
    line_in_file : str
        A single line in main_code_filename that we can look for to make sure decompilation worked.
    items_in_pythonscript_res : int
        The number of items that were supposed to be unpacked from the PYTHONSCRIPT resource, including decompiled
        files. (If there were 3 marshalled code objects inside the PYTHONSCRIPT that get dumped to 3 pyc files, and all
        successfully decompile, there will be 6 total files).
    bytecode_version : int, optional
        The version of Python bytecode used in test_file (magic number).
    items_in_py2exe_archive : int, optional
        The number of items that were supposed to be unpacked from the Py2Exe zipfile archive, including decompiled
        files.
    size_of_dis : int, optional
        Size of the dis.pyc file in bytes, if included in the archive.
    remapping_file : str, optional
        Path to the remap remapping.txt file, if this file uses custom opcodes. Path is relative to tests/test_data dir.
    """

    python_version: float
    test_file: str
    file_sha256: str
    main_code_filename: str
    line_in_file: str
    items_in_pythonscript_res: int
    bytecode_version: int = dataclasses.field(default=0)
    items_in_py2exe_archive: int = dataclasses.field(default=0)
    size_of_dis: int = dataclasses.field(default=0)
    remapping_file: str = dataclasses.field(default="")


@dataclasses.dataclass
class PyInstallerTestParameters:
    """PyInstaller PE parameters for pytest's parameterized testing.

    Attributes
    ----------
    python_version : float
        The version of Python used in test_file.
    test_file : str
        The path to the test file on disk, relative to the tests/test_data dir.
    file_sha256 : str
        The SHA256 digest of test_file.
    main_code_filename : str
        The name of the Python file entrypoint within the frozen sample that will be unpacked.
    line_in_file : str
        A single line in main_code_filename that we can look for to make sure decompilation worked.
    items_in_pyinstarchive : int
        The number of items that were supposed to be unpacked from the CPython Archive, including decompiled
        files. (If there were 3 marshalled code objects inside that get dumped to 3 pyc files, and all
        successfully decompile, there will be 6 total files).
    zlib_archive_name: str
        The name of the PyInstaller ZlibArchive contained within the CArchive.
    items_in_zlibarchive : int
        The number of items that were supposed to be unpacked from the ZlibArchive, including decompiled
        files.
    size_of_dis : int
        Size of the dis.pyc file in bytes, if included in the archive.
    bytecode_version : int, optional
        The version of Python bytecode used in test_file (magic number).
    remapping_file : str, optional
        Path to the remap remapping.txt file, if this file uses custom opcodes. Path is relative to tests/test_data dir.
    """

    python_version: float
    test_file: str
    file_sha256: str
    main_code_filename: str
    line_in_file: str
    items_in_pyinstarchive: int
    zlib_archive_name: str
    items_in_zlibarchive: int
    size_of_dis: int
    bytecode_version: int = dataclasses.field(default=0)
    remapping_file: str = dataclasses.field(default="")


@dataclasses.dataclass
class RemapTestParameters:
    """Remap execution parameters for pytest's parameterized testing.

    Attributes
    ----------
    test_file : str
        The path to the test file on disk, relative to the tests/test_data dir.
    file_sha256 : str
        The SHA256 digest of test_file.
    method : str
        The primary flag you want to run `remap` with.  This can be
            - check-remapping
            - opcode-file
            - standard-bytecode-path
            - megafile
    correct_remapping_file : str, optional
        The path to the expected remapping.txt file, relative to the tests/test_data directory.
    options : str, optional
        Any additional flags or arguments to add to the remap command.
    method_arg: str, optional
        The argument for the method flag (typically a path, but can also be a version number).
    expected_status_code : Union[int, None], optional
        Any non-zero status codes that should be considered successes.
    """

    test_file: str
    file_sha256: str
    method: str
    correct_remapping_file: str = dataclasses.field(default="")
    options: str = dataclasses.field(default="")
    method_arg: str = dataclasses.field(default="")
    expected_status_code: Union[int, None] = dataclasses.field(default=None)


@dataclasses.dataclass
class ZipTestParameters:
    """Zipfile artifact parameters for pytest's parameterized testing.

    Attributes
    ----------
    test_file : str
        The path to the test file on disk, relative to the tests/test_data dir.
    file_sha256 : str
        The SHA256 digest of test_file.
    output_files : int
        The number of files inside the output directory after decompilation. This will include the original items in
        the zipfile, any bytecode files that were able to be decompiled, as well as any log files from pydecipher.
    file_to_check : str
        A Python source code file that should be contained within the zipfile, for purposes of checking that
        decompilation worked.
    file_size : int
        The size in bytes of file_to_check.
    file_line: str
        A single line in file_to_check that we can look for to make sure decompilation worked.
    remapping_file : str, optional
        Path to the remap remapping.txt file, if this file uses custom opcodes. Path is relative to tests/test_data dir.
    options : str, optional
        Any additional flags or arguments to add to the remap command.
    """

    test_file: str
    file_sha256: str
    output_files: int
    file_to_check: str
    file_size: int
    file_line: str
    remapping_file: str = dataclasses.field(default="")
    options: str = dataclasses.field(default="")


def set_up_tmp_dir(dir_name: str) -> pathlib.Path:
    """Set up a temporary working directory for a test.

    Parameters
    ----------
    dir_name: str
        The name of the directory to create.

    Returns
    -------
    pathlib.Path
        The path to the created directory.
    """
    frame: NamedTuple = inspect.stack()[1]
    module: ModuleType = inspect.getmodule(frame[0])
    caller_file: str = module.__file__

    parent_dir: pathlib.Path = pathlib.Path(caller_file).parents[0]
    tmp_dir: pathlib.Path = parent_dir.joinpath(dir_name)
    if tmp_dir.exists() and tmp_dir.is_dir():
        shutil.rmtree(str(tmp_dir))
    tmp_dir.mkdir()
    return tmp_dir


def sha256_file(filepath: pathlib.Path) -> str:
    """Calculate the SHA256 hash digest of the given filepath.

    Taken from https://gist.github.com/aunyks/042c2798383f016939c40aa1be4f4aaf
    """
    BLOCKSIZE: int = 65536
    sha256: Any = hashlib.sha256()
    input_file: BinaryIO
    with filepath.open(mode="rb") as input_file:
        file_buffer: bytes = input_file.read(BLOCKSIZE)
        while len(file_buffer) > 0:
            sha256.update(file_buffer)
            file_buffer = input_file.read(BLOCKSIZE)
    return sha256.hexdigest()
