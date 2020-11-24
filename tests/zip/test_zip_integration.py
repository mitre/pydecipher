# -*- coding: utf-8 -*-
"""Integration tests for the Zip archive artifact type."""

import os
import pathlib
import shutil
from typing import List, TextIO

import pytest

import pydecipher
import tests.utils as utils

__all__ = ["test_zip"]

_all_test_data = [
    # utils.ZipTestParameters(
    #     test_file="zip/triton",
    #     file_sha256="bef59b9a3e00a14956e0cd4a1f3e7524448cbe5d3cc1295d95a15b83a3579c59",
    #     output_files=164,
    #     options="-v -d",
    #     file_to_check="TsHi.py",
    #     file_size=13644,
    #     file_line=r"""second_try = self.AppendProgramMin(b'\xff\xff`8\x02\x00\x00D \x00\x80N', func_count, prog_cnt)""",
    # ),
    # utils.ZipTestParameters(
    #     test_file="obfuscated_opcodes/pyxie_rat/pyxie_bytecode_zip",
    #     file_sha256="d1429f54baaad423a8596140a3f70f7d9f762373ad625bda730051929463847d",
    #     remapping_file="obfuscated_opcodes/pyxie_rat/megafile-remapping.txt",
    #     options="-v -d",
    #     output_files=711,
    #     file_to_check="lazagne/config/change_privileges.corrected.py",
    #     file_size=6080,
    #     file_line=r"""hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, os.getpid())""",
    # ),
]


@pytest.mark.parametrize("test_data", _all_test_data)
def test_zip(keep_output: bool, test_data: utils.ZipTestParameters) -> None:
    """Integration test for Zip archive artifact type of pydecipher.

    Parameters
    ----------
    keep_output: bool
        Whether or not the temporary output directory should be kept after the function successfully iterates through
        a test. Can be set with the -K or --keep-output flag to pytest.
    test_data: pydecipher.tests.utils.ZipTestParameters
        A dataclass which has information related to the Zip archive artifact type integration test.

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
    if test_data.options:
        new_args: List[str] = test_data.options.split()
        new_args.extend(args)
        args = new_args

    if test_data.remapping_file:
        remapping_file: pathlib.Path = utils.PYD_TEST_DATA_DIR.joinpath(test_data.remapping_file)
        args.extend(["--remapping-file", str(remapping_file)])
    args.append(str(test_file))
    pydecipher.main.run(args)

    # Check that the main code file was successfully produced
    main_code_file: pathlib.Path = tmp_dir / test_data.file_to_check
    assert main_code_file.exists()
    assert main_code_file.is_file()
    lines_to_check: List[str] = [test_data.file_line]

    mcf: TextIO
    with main_code_file.open() as mcf:
        lines_in_file: List[str] = [line.strip() for line in mcf.readlines()]
        line: str
        for line in lines_to_check:
            assert line in lines_in_file

    # Check total # of items extracted from zip archive
    assert len(os.listdir(tmp_dir)) == test_data.output_files
    assert main_code_file.stat().st_size == test_data.file_size

    if not keep_output:
        shutil.rmtree(tmp_dir)
