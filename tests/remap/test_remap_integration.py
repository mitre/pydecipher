# -*- coding: utf-8 -*-
"""Integration tests for the remap command."""
import pathlib
import shutil
import zipfile
from typing import Dict, List, TextIO

import pytest

import pydecipher
import tests.utils as utils
from pydecipher import remap
from pydecipher.utils import slugify

__all__ = ["test_remap"]

_all_test_data: List[utils.RemapTestParameters] = [
    # Check opcode-validity test
    utils.RemapTestParameters(
        test_file="obfuscated_opcodes/hello_world/correct_remapping.txt",
        file_sha256="429a188de6065218473c9b4491ac66dbc367dc5ea733fe20782478c3a4fde237",
        method="check-remapping",
    ),
    utils.RemapTestParameters(
        test_file="obfuscated_opcodes/pyxie_rat/megafile-remapping.txt",
        file_sha256="4a70b3b849aed384d5cb862a231540eaffc9e29bd15aee4ab90d1e1bbdeae1f7",
        method="check-remapping",
    ),
    utils.RemapTestParameters(
        test_file="other/incomplete-remapping.txt",
        file_sha256="df9fdbca0646c64cc3f3b02b3033c4d887c49bc48667e550cac509e7d117d791",
        method="check-remapping",
        expected_status_code=1,
    ),
    # Opcode-constants walking tests
    utils.RemapTestParameters(
        test_file="obfuscated_opcodes/hello_world/opcode.pyc",
        file_sha256="aa599b111b74a73b88194759152b92c19ff09e955bc5500a9642aae8002df558",
        method="opcode-file",
        correct_remapping_file="obfuscated_opcodes/hello_world/correct_remapping.txt",
    ),
    utils.RemapTestParameters(
        test_file="obfuscated_opcodes/hello_world/opcode_wrong_suffix.abc",
        file_sha256="aa599b111b74a73b88194759152b92c19ff09e955bc5500a9642aae8002df558",
        method="opcode-file",
        correct_remapping_file="obfuscated_opcodes/hello_world/correct_remapping.txt",
    ),
    utils.RemapTestParameters(
        test_file="obfuscated_opcodes/hello_world/opcode_headerless.pyc",
        file_sha256="7664dc807720b7fe6b7c3df7ddc0d391a2f3486ef66285257988536a6c374564",
        method="opcode-file",
        options="--version 3.6",
        correct_remapping_file="obfuscated_opcodes/hello_world/correct_remapping.txt",
    ),
    utils.RemapTestParameters(
        test_file="obfuscated_opcodes/hello_world/opcode_no_magic_bytes.pyc",
        file_sha256="4df7acef2abf307e27efce608b96ca441bdc6070310404ea265deb5849f32e91",
        method="opcode-file",
        options="--version 3.6",
        correct_remapping_file="obfuscated_opcodes/hello_world/correct_remapping.txt",
    ),
    utils.RemapTestParameters(
        test_file="obfuscated_opcodes/hello_world/opcode_wrong_magic_bytes.pyc",
        file_sha256="381491572c277329167b39ebbd06533e04cc19cdeb866958554368277cc23190",
        method="opcode-file",
        options="--version 3.6",
        correct_remapping_file="obfuscated_opcodes/hello_world/correct_remapping.txt",
    ),
]


@pytest.mark.parametrize("test_data", _all_test_data)
def test_remap(keep_output: bool, test_data: utils.RemapTestParameters) -> None:
    """Integration test for remap command.

    Parameters
    ----------
    keep_output: bool
        Whether or not the temporary output directory should be kept after the function successfully iterates through
        a test. Can be set with the -K or --keep-output flag to pytest.
    test_data: pydecipher.tests.utils.RemapTestParameters
        A dataclass which has information related to the remap integration test.

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

    if zipfile.is_zipfile(test_file):
        unzipped_dir: pathlib.Path = tmp_dir / f"{slugify(test_file.name)}_unzipped"
        zip_ref: TextIO
        with zipfile.ZipFile(test_file, "r") as zip_ref:
            zip_ref.extractall(unzipped_dir)
        test_file = unzipped_dir
    args: List[str] = [
        "-v",
        "-o",
        f"{str(tmp_dir)}",
        f"--{test_data.method}",
    ]

    if test_data.method_arg:
        if test_data.method == "standard-bytecode-path":
            method_arg: str = str(utils.PYD_TEST_DATA_DIR.joinpath(test_data.method_arg))
        else:
            method_arg: str = test_data.method_arg
        args.append(str(method_arg))
    if test_data.options:
        new_args: List[str] = test_data.options.split()
        new_args.extend(args)
        args = new_args
    args.append(str(test_file))

    if test_data.expected_status_code:
        pytest_wrapped_e: Exception
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            remap.run(args)
        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == test_data.expected_status_code
    else:
        remap.run(args)

    if test_data.method != "check-remapping":
        generated_remapping_file: List[pathlib.Path] = list(tmp_dir.rglob("remapping.txt"))
        assert len(generated_remapping_file) == 1
        generated_remapping_file: pathlib.Path = generated_remapping_file[0]
        generated_opmap: Dict[str, int] = pydecipher.bytecode.create_opmap_from_file(generated_remapping_file)
        correct_remapping: pathlib.Path = utils.PYD_TEST_DATA_DIR.joinpath(test_data.correct_remapping_file)
        correct_opmap: Dict[str, int] = pydecipher.bytecode.create_opmap_from_file(correct_remapping)
        assert generated_opmap == correct_opmap

    if not keep_output:
        shutil.rmtree(tmp_dir)
