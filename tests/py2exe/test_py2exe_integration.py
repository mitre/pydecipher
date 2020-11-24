# -*- coding: utf-8 -*-
"""Integration tests for the Py2Exe artifact type."""

import os
import pathlib
import shutil
from typing import List, TextIO

import pytest

import pydecipher
import tests.utils as utils

__all__ = ["test_py2exe"]

_all_test_data = [
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=2.3,
    #    bytecode_version=62021,
    #    test_file="py2exe/py2exe_23",
    #    file_sha256="7562c17e1886e4841950a18bb0a5e3134e756f69a1ea0ece4e7a947b2683e710",
    #    main_code_filename="boot_com_servers.py",
    #    line_in_file="""if arg.find('/automate') > -1:""",
    #    items_in_pythonscript_res=6,
    # ),
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=2.4,
    #    bytecode_version=62061,
    #    test_file="py2exe/py2exe_24",
    #    file_sha256="af47b2da6aea5c7a7b3e19f8470c07267ccac8cc8eeb4ad1bc10fbea0d71888b",
    #    main_code_filename="pyscrabble-main.py",
    #    line_in_file="""warnings.filterwarnings('ignore')""",
    #    items_in_pythonscript_res=4,
    # ),
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=2.5,
    #    bytecode_version=62131,
    #    test_file="py2exe/py2exe_25",
    #    file_sha256="cb374e12f7b465985f8fdb75a6eff9065a8b7162b3cf6bdd9e47b3dbefd97235",
    #    main_code_filename="dover.py",
    #    line_in_file="""macos = sys.platform in ('Darwin', 'darwin')""",
    #    items_in_pythonscript_res=4,
    # ),
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=2.6,
    #    bytecode_version=62161,
    #    test_file="py2exe/py2exe_26",
    #    file_sha256="089f234e111f41c0f907e7d8b7dca7d4473bc2b30072dc6b4804e86e9a19aedb",
    #    main_code_filename="dtascli.py",
    #    line_in_file="""_retrive_object('BlackList', filename, None)""",
    #    items_in_pythonscript_res=6,
    #    items_in_py2exe_archive=226,
    #    size_of_dis=6177,
    # ),
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=2.7,
    #    bytecode_version=62211,
    #    test_file="py2exe/py2exe_27",
    #    file_sha256="9a2f37a4f90945451774ad3ea69281e5056843f0fc7fe9abc1c5d0ff3706f448",
    #    main_code_filename="thg.py",
    #    line_in_file="""qtrun(run, ui.ui(), **opts)""",
    #    items_in_pythonscript_res=4,
    # ),
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=3.3,
    #    bytecode_version=3230,
    #    test_file="py2exe/py2exe_33",
    #    file_sha256="5bfd86b9a6c58c2799e7e51990b25b21ff8214d1041a8924edf9e2c4f033c620",
    #    main_code_filename="a.py",
    #    line_in_file="""os._exit(0)""",
    #    items_in_pythonscript_res=6,
    #    items_in_py2exe_archive=235,
    #    size_of_dis=11009,
    # ),
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=3.4,
    #    bytecode_version=3310,
    #    test_file="py2exe/py2exe_34",
    #    file_sha256="3aa44916e758d653f9664a18292dbd0179a747f7decfd02a013a9ca5241427fe",
    #    main_code_filename="xlsx2csv.py",
    #    line_in_file="""return fName + '_' + sheetName[5:] + '.csv'""",
    #    items_in_pythonscript_res=8,
    #    items_in_py2exe_archive=210,
    #    size_of_dis=14569,
    # ),
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=3.5,
    #    bytecode_version=3351,
    #    test_file="py2exe/py2exe_35",
    #    file_sha256="a7a2269db0b90815390b8986b706212647506dfb988798b937ebf1b92e188d41",
    #    main_code_filename="service_info.py",
    #    line_in_file="""service_module_names = ['cagent']""",
    #    items_in_pythonscript_res=8,
    #    items_in_py2exe_archive=280,
    #    size_of_dis=14781,
    # ),
    # utils.Py2ExeTestParameters(  # nonmalicious VT sample
    #    python_version=3.6,
    #    bytecode_version=3379,
    #    test_file="py2exe/py2exe_36",
    #    file_sha256="30925f55040295b1d2a70e4257b6a69897075554d9cf17ee84e9ba8b85625b82",
    #    main_code_filename="zpatcher.py",
    #    line_in_file="""pos = m.find(bytes.fromhex('33042433542404'))""",
    #    items_in_pythonscript_res=8,
    #    items_in_py2exe_archive=224,
    #    size_of_dis=10646,
    # ),
]


@pytest.mark.parametrize("test_data", _all_test_data)
def test_py2exe(keep_output: bool, test_data: utils.Py2ExeTestParameters) -> None:
    """Integration test for Py2Exe artifact type of pydecipher.

    Parameters
    ----------
    keep_output: bool
        Whether or not the temporary output directory should be kept after the function successfully iterates through
        a test. Can be set with the -K or --keep-output flag to pytest.
    test_data: pydecipher.tests.utils.Py2ExeTestParameters
        A dataclass which has information related to the Py2Exe artifact type integration test.

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

    # pydecipher.unpack(test_file, output_dir=str(tmp_dir))
    # pydecipher.bytecode.process_pycs(rglob_limit_depth(tmp_dir, '*.[pP][yY][cC]', 2))
    # pydecipher.artifact_types.py2exe.PYTHONSCRIPT.cleanup(tmp_dir)
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
    lines_to_check: List[str] = [test_data.line_in_file]

    # Check that the main code file was successfully produced
    main_code_file: pathlib.Path = tmp_dir / "pythonscript_output" / test_data.main_code_filename
    assert main_code_file.exists()
    assert main_code_file.is_file()

    mcf: TextIO
    with main_code_file.open() as mcf:
        lines_in_file: List[str] = [line.strip() for line in mcf.readlines()]
        if test_data.bytecode_version:
            lines_to_check.append(
                "# Python bytecode {} ({})".format(str(test_data.python_version), str(test_data.bytecode_version))
            )
        line: str
        for line in lines_to_check:
            assert line in lines_in_file

    # Check total # of items extracted from PE
    if test_data.items_in_pythonscript_res:
        assert len(os.listdir(tmp_dir / "pythonscript_output")) == test_data.items_in_pythonscript_res

    # Check that the py2exe archive exists and was successfully extracted
    if test_data.items_in_py2exe_archive:
        py2exe_archive: pathlib.Path = tmp_dir.joinpath("overlay_data")
        unzipped_archive: pathlib.Path = tmp_dir.joinpath("overlay_data_output")
        assert py2exe_archive.exists()
        assert unzipped_archive.exists()
        assert unzipped_archive.is_dir()
        assert len(os.listdir(unzipped_archive)) == test_data.items_in_py2exe_archive
        assert unzipped_archive.joinpath("dis.pyc").stat().st_size == test_data.size_of_dis

    if not keep_output:
        shutil.rmtree(tmp_dir)
