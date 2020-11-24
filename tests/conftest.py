# -*- coding: utf-8 -*-
"""Configuration functions for pytest."""
import _pytest


def pytest_addoption(parser) -> None:
    """Add the keep-output option for our tests.

    Triggered by -K or --keep-output. Will prevent the output of pydecipher
    or remap from being deleted.
    """
    parser.addoption(
        "-K",
        "--keep-output",
        action="store_true",
        help="keep output after testing instead of deleting temporary directories",
    )


def pytest_generate_tests(metafunc: _pytest.python.Metafunc) -> None:
    """
    Add the keep-ouput boolean to function arguments if it was detected on CLI.

    Parameters
    ----------
    metafunc
        The test function about to run
    """
    # This is called for every test. Only get/set command line arguments
    # if the argument is specified in the list of test "fixturenames".
    option_value: bool = metafunc.config.option.keep_output
    if "keep_output" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("keep_output", [option_value])
