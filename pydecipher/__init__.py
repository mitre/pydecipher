# -*- coding: utf-8 -*-
"""Set up logging and includes some logging-related functions.

Also includes the decorator function for registering artifact classes.

Attributes
----------
name : str
    The package name.
PYD_ROOT_DIR : pathlib.Path
    The root directory of the package code on this system. Used in testing to
    find the sample files.
logger : logging.Logger
    The logger instance that pydecipher uses to output log messages to the
    console and pydecipher log file.
log_format : logging.Formatter
    The format of the log lines used by `pydecipher.__init__.logger`.
log_path : pathlib.Path
    If a log file exists for this running instance of pydecipher, its location
    should be stored in this variable. This is used in the multi-processed
    decompilation, so that new pydecipher processes can continue writing to the
    same log file as the initial process.
verbose_enabled : bool
    Whether or not verbose logging is enabled for this instance of pydecipher.
quiet_enabled : bool
    Whether or not console output logging has disabled for this instance of
    pydecipher.
ARTIFACT_TYPES : Dict[str, type]
    This dictionary will hold all the different types of artifacts that are
    'unpack-able' in :meth:`pydecipher.main.unpack`. The format of the entries
    <Class name: Instance of the class>
"""
import logging
import pathlib
import sys
from typing import Dict, Union

__all__ = [
    "__version__",
    "name",
    "PYD_ROOT_DIR",
    "logger",
    "log_format",
    "log_path",
    "ARTIFACT_TYPES",
    "register",
    "get_logging_options",
    "set_logging_options",
    "unpack",
]

__version__: str = "1.0.0"
name: str = "pydecipher"

PYD_ROOT_DIR: pathlib.Path = pathlib.Path(__file__).parents[1]
ARTIFACT_TYPES: Dict[str, type] = {}

# Configure the logging for pydecipher module.
logger: logging.Logger = logging.getLogger(name)
logger.setLevel(logging.DEBUG)
log_format: logging.Formatter = logging.Formatter("%(asctime)s: %(message)s")
_stdout_console_handler: logging.StreamHandler = logging.StreamHandler(sys.stdout)
_stdout_console_handler.setLevel(logging.INFO)
# Log only INFO and DEBUG levels to stdout.
_stdout_console_handler.addFilter(lambda record: record.levelno <= logging.INFO)
_stdout_console_handler.setFormatter(log_format)
_stderr_console_handler: logging.StreamHandler = logging.StreamHandler()
_stderr_console_handler.setLevel(logging.WARNING)
_stderr_console_handler.setFormatter(log_format)
# Log WARNING and above to stderr.
_stderr_console_handler.addFilter(lambda record: record.levelno >= logging.WARNING)
logger.addHandler(_stdout_console_handler)
logger.addHandler(_stderr_console_handler)
log_path: pathlib.Path = None
verbose_enabled: bool = False
quiet_enabled: bool = False


def register(artifact_class: type) -> type:
    """Register artifact classes as unpack-able (this is a decorator).

    Parameters
    ----------
    artifact_class : type
        :meth:`pydecipher.main.unpack` will try to instantiate this class with
        the artifact passed into pydecipher to figure out what type of artifact
        is being analyzed.

    Returns
    -------
    type
        The class object argument, unchanged.
    """
    ARTIFACT_TYPES[artifact_class.__name__] = artifact_class
    return artifact_class


def _quiet_console_output() -> None:
    """Quiets pydecipher from writing to stdout or stderr.

    Program output will still be logged to file.
    """
    global quiet_enabled
    handler: logging.StreamHandler
    for handler in logger.handlers:
        logger.removeHandler(handler)
    quiet_enabled = True


def _enable_verbose() -> None:
    """Set the library-wide logging level to be verbose."""
    global verbose_enabled
    handler: logging.StreamHandler
    for handler in logger.handlers:
        handler.setLevel(logging.DEBUG)
    verbose_enabled = True


def get_logging_options() -> Dict[str, Union[bool, pathlib.Path]]:
    """Retrieve the library-wide logging settings.

    Returns
    -------
    Dict[str, Union[bool, pathlib.Path]]
        A dictionary of the logging settings.
    """
    return {"verbose": verbose_enabled, "quiet": quiet_enabled, "log_path": log_path}


def set_logging_options(**kwargs):
    """Set the library-wide logging settings.

    Parameters
    ----------
    **kwargs
        Arbitrary keyword arguments. These can be the following:

        verbose: bool
            True will enable verbose logging.
        quiet: bool
            True will silence all console logging.
        log_path: pathlib.Path
            If a path object is passed in as the log_path, the running
            instance of pydecipher will continue logging to that file.

    Notes
    -----
    Quiet and verbose are mutually exclusive, but we don't perform the check
    here again because this is enforced by argparse in
    :func:`pydecipher.main._parse_args`.
    """
    global log_path
    if kwargs.get("verbose", []):
        _enable_verbose()
    if kwargs.get("quiet", []):
        _quiet_console_output()
    if kwargs.get("log_path", []):
        log_path = kwargs["log_path"]
        file_handler: logging.FileHandler = logging.FileHandler(log_path)
        file_handler.setFormatter(log_format)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)


# Exports
from pydecipher.main import unpack  # noqa
