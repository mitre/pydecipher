# -*- coding: utf-8 -*-
"""Integration tests for the PyInstaller artifact type."""
import os
import pathlib
import shutil
from typing import List, TextIO

import pytest

import pydecipher
import tests.utils as utils

__all__ = ["test_pyinstaller"]

_all_test_data = [
    # utils.PyInstallerTestParameters(  # real VT sample
    #     python_version=2.5,
    #     bytecode_version=62131,
    #     test_file="pyinstaller/pyinstaller_25",
    #     file_sha256="04a3721bb28fc63aac4e53207ebfda270f0bcd442a87ee4e0eaff62bd169963c",
    #     main_code_filename="coordinator.py",
    #     line_in_file="""if __name__ == "__main__":""",
    #     items_in_pyinstarchive=14,
    #     zlib_archive_name="out00-PYZ.pyz",
    #     items_in_zlibarchive=346,
    #     size_of_dis=6492,
    # ),
    # utils.PyInstallerTestParameters(  # real VT sample
    #     python_version=2.6,
    #     bytecode_version=62161,
    #     test_file="pyinstaller/pyinstaller_26",
    #     file_sha256="96687dd580595875304498148cb1953a851c2e921bdfc3e836910c155c8c5418",
    #     main_code_filename="lab.py",
    #     line_in_file="openf = open('not.txt','r')",
    #     items_in_pyinstarchive=32,
    #     zlib_archive_name="out00-PYZ.pyz",
    #     items_in_zlibarchive=342,
    #     size_of_dis=6521,
    # ),
    # utils.PyInstallerTestParameters(  # real VT sample
    #     python_version=2.7,
    #     bytecode_version=62211,
    #     test_file="pyinstaller/pyinstaller_27",
    #     file_sha256="e50c253d08001490f9a2850ca8b2054be1503bf6efffe799c9aa12f880cf264f",
    #     main_code_filename="CustomBindShell.py",
    #     line_in_file="sock.bind(('0.0.0.0', 12233))",
    #     items_in_pyinstarchive=26,
    #     zlib_archive_name="out00-PYZ.pyz",
    #     items_in_zlibarchive=196,
    #     size_of_dis=6060,
    # ),
    # utils.PyInstallerTestParameters(  # real VT sample
    #     python_version=3.3,
    #     bytecode_version=3230,
    #     test_file="pyinstaller/pyinstaller_33",
    #     file_sha256="879fece71f5072a847772c94a80d7e76b83648ce11c328f6dd394634f7fd9d1f",
    #     main_code_filename="Net.py",
    #     line_in_file="s.send('Comando:'.encode())",
    #     items_in_pyinstarchive=58,
    #     zlib_archive_name="out00-PYZ.pyz",
    #     items_in_zlibarchive=520,
    #     size_of_dis=10757,
    # ),
    # utils.PyInstallerTestParameters(  # real VT sample
    #     python_version=3.4,
    #     bytecode_version=3310,
    #     test_file="pyinstaller/pyinstaller_34",
    #     file_sha256="271ba0f829f2260c7e767e3ea42dca51f900336e82d859c08ca525d8067734f1",
    #     main_code_filename="RPS.py",
    #     line_in_file=r"print(name.upper() + 'WINS:\t' + str(playerwon))",
    #     items_in_pyinstarchive=31,
    #     zlib_archive_name="out00-PYZ.pyz",
    #     items_in_zlibarchive=183,
    #     size_of_dis=14553,
    # ),
    # utils.PyInstallerTestParameters(  # real VT sample
    #     python_version=3.5,
    #     bytecode_version=3350,
    #     test_file="pyinstaller/pyinstaller_35",
    #     file_sha256="65d4a2daa6a6e65bfef08b797f39b2342bb1d6d052d7dd74f680ad9ceb046870",
    #     main_code_filename="MainAUS.py",
    #     line_in_file="window.setWindowIcon(QtGui.QIcon('icon.png'))",
    #     items_in_pyinstarchive=18,
    #     zlib_archive_name="out00-PYZ.pyz",
    #     items_in_zlibarchive=538,
    #     size_of_dis=14751,
    # ),
    # utils.PyInstallerTestParameters(  # real VT sample
    #     python_version=3.6,
    #     bytecode_version=3379,
    #     test_file="pyinstaller/pyinstaller_36",
    #     file_sha256="5d2677c7376b128813a15ce3e56f4badb9a4a1a88e2d536099e4ba1770bc39ba",
    #     main_code_filename="DocPacket.py",
    #     line_in_file="print('развыделяю виджет ' + image.filename)",
    #     items_in_pyinstarchive=22,
    #     zlib_archive_name="out00-PYZ.pyz",
    #     items_in_zlibarchive=1637,
    #     size_of_dis=14162,
    # ),
    utils.PyInstallerTestParameters(  # obfuscated opcode
        python_version=3.6,
        test_file="obfuscated_opcodes/hello_world/test_exe",
        file_sha256="497d95671caf273355bdaffc3f31bc3bcf8e73d436ede9ee285cf27e3cb0c7f7",
        main_code_filename="test.py",
        remapping_file="obfuscated_opcodes/hello_world/correct_remapping.txt",
        line_in_file="""with open('this_is_a_test.txt', 'w') as (f):""",
        items_in_pyinstarchive=65,
        zlib_archive_name="out00-PYZ.pyz",
        items_in_zlibarchive=135,
        size_of_dis=14162,
    ),
]


@pytest.mark.parametrize("test_data", _all_test_data)
def test_pyinstaller(keep_output: bool, test_data: utils.PyInstallerTestParameters) -> None:
    """Integration test for PyInstaller artifact type of pydecipher.

    Parameters
    ----------
    keep_output: bool
        Whether or not the temporary output directory should be kept after the function successfully iterates through
        a test. Can be set with the -K or --keep-output flag to pytest.
    test_data: pydecipher.tests.utils.PyInstallerTestParameters
        A dataclass which has information related to the PyInstaller artifact type integration test.

    Raises
    ------
    AssertionError
        A test condition has failed.
    """
    test_file: pathlib.Path = utils.PYD_TEST_DATA_DIR.joinpath(test_data.test_file)
    pydecipher.utils.check_read_access(test_file)
    assert utils.sha256_file(test_file) == test_data.file_sha256
    tmp_dir_name: str = "tmp_{}_{}".format(str(test_file.name).replace(".", ""), test_data.file_sha256[:10])
    tmp_dir: pathlib.Path = utils.set_up_tmp_dir(tmp_dir_name)

    args: List[str] = [
        "-v",
        "-o",
        f"{str(tmp_dir)}",
    ]

    if test_data.remapping_file:
        remapping_file: pathlib.Path = utils.PYD_TEST_DATA_DIR.joinpath(test_data.remapping_file)
        args.extend(["--remapping-file", str(remapping_file)])
    args.append(str(test_file))
    pydecipher.main.run(args)

    # Check that the main code file was successfully produced
    main_code_file: pathlib.Path = tmp_dir / "overlay_data_output" / test_data.main_code_filename
    assert main_code_file.exists()
    assert main_code_file.is_file()
    lines_to_check: List[str] = [test_data.line_in_file]

    if test_data.python_version >= 2.7:
        # 2.5 seems to include the uncompiled .py file in the archive,
        # and therefore uncompyle does not create it + append the version line
        if test_data.bytecode_version:
            lines_to_check.append(
                "# Python bytecode {} ({})".format(str(test_data.python_version), str(test_data.bytecode_version))
            )

    mcf: TextIO
    with main_code_file.open() as mcf:
        lines_in_file: List[str] = [line.strip() for line in mcf.readlines()]
        line: str
        for line in lines_to_check:
            assert line in lines_in_file

    # Check total # of items extracted from PE's Pyinstaller archive
    assert len(os.listdir(tmp_dir.joinpath("overlay_data_output"))) == test_data.items_in_pyinstarchive

    # Check that the ZlibArchive was successfully extracted
    zlib_archive_name: str = test_data.zlib_archive_name.split(".pyz")[0].lower()
    zlib_archive: pathlib.Path = tmp_dir / "overlay_data_output" / f"{zlib_archive_name}_output"
    assert zlib_archive.exists()
    assert zlib_archive.is_dir()
    assert len(os.listdir(zlib_archive)) == test_data.items_in_zlibarchive
    assert zlib_archive.joinpath("dis.pyc").stat().st_size == test_data.size_of_dis

    if not keep_output:
        shutil.rmtree(tmp_dir)
