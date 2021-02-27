# -*- coding: utf-8 -*-
"""Contains the functionality for the ``pydecipher`` command.

This module is the entry point of the pydecipher command. It is responsible for
parsing command line options as well as running the processing pipeline.

This file is reserved for high-level orchestration functions that control the
flow of the program as determined by the output/return values of specialized
functions. General utility functions and functions that deal with the
manipulation of bytecode should go in :ref:`utils.py <utils>` and
:ref:`bytecode.py <bytecode>`, respectively. Artifact specific parsing code
should go in the appropriate files in the artifact_types directory. Functions
related to opcode remapping and opcode obfuscation should go in remap.py.
"""
import argparse
import datetime
import io
import json
import logging
import os
import pathlib
import sys
from typing import Dict, Generator, Iterable, List, Union

import pydecipher
from pydecipher import artifact_types, bytecode, logger, utils

__all__ = ["_parse_args", "unpack", "run"]


def _parse_args(args: List = None) -> argparse.Namespace:
    """Parse pydecipher's arguments and accordingly set run-time options.

    Usually these arguments will come from the command line, however if
    pydecipher is being called from code, `_args` may be passed in as a
    list.

    Parameters
    ----------
    args : List, optional
        A list of arguments/flags. If you are calling pydecipher from code,
        you need to pass in your command line as a space-delimited list.
        i.e. for ``pydecipher -v example.exe``,  args would be
        ['-v', 'example.exe'].

    Returns
    -------
    argparse.Namespace
      The populated namespace of options for pydecipher's runtime.
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog=pydecipher.name,
        description="A tool to aid in the analysis of frozen Python artifacts.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {pydecipher.__version__}",
    )
    parser.add_argument("artifact_path", type=str, help="Path to python artifact")
    output_settings = parser.add_mutually_exclusive_group()
    output_settings.add_argument("-q", "--quiet", action="store_true", help="Suppress all stdout/err output")
    output_settings.add_argument("-v", "--verbose", action="store_true", help="Show verbose output")
    parser.add_argument(
        "-d",
        "--decompile-all",
        action="store_true",
        help="Decompile all pyc files in addition to the top-level files found in each artifact.",
    )
    parser.add_argument(
        "--version-hint",
        type=str,
        help="The version of Python used to freeze the artifact.",
    )
    parser.add_argument(
        "-r",
        "--remapping-file",
        type=str,
        help="A path to a pydecipher remapping file",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=False,
        help=(
            "Location to dump the output extracted from the artifact. If not specified, a pydecipher_output_* "
            "directory will be created in the current working directory."
        ),
    )
    if args:
        return parser.parse_args(args)
    else:
        return parser.parse_args()


def unpack(python_artifact: os.PathLike, output_dir: str = None, **kwargs) -> None:
    """Recursively extract interesting resources from the Python artifact.

    This function will cycle through all the registered ARTIFACT_TYPES. See
    usages of :py:meth:`pydecipher.__init__.register` for the creation of this
    list.


    ARTIFACT_TYPES consists of the different 'unpackable', registered
    (via decorator) Python artifact classes in a dictionary of the format
    <Artifact_Name : Class Instance of Artifact_Name>. A class's constructor
    should raise a TypeError if is being instantiated with something that
    isn't the correct type (i.e. Py2Exe resource being passed to a
    PyInstaller archive constructor).

    Parameters
    ----------
    python_artifact : pathlib.Path or io.IOBase (file-like object)
        The path to the Python artifact
    output_dir : str, optional
        Where to dump the extracted output of artifact parsers. If no
        directory is specified, a directory will be created in the
        current working directory.
    **kwargs
        Arbitrary keyword arguments. Including, but not limited to:

            version_hint: str
                The (potential) Python version of the artifact. If you know
                the version, you should pass it in. Otherwise, pydecipher
                will try to automatically figure out what version was used
                through string-analysis (and possibly brute-force decompilation).
                If
    """
    if output_dir:
        output_dir: pathlib.Path = pathlib.Path(output_dir).resolve()
    type_instance: type = None
    logger.info(f"[*] Unpacking {python_artifact}")
    for type_, class_ in pydecipher.ARTIFACT_TYPES.items():
        logger.debug(f"[*] Checking {type_} magic for file {python_artifact.name}")
        try:
            type_instance = class_(python_artifact, output_dir=output_dir, **kwargs)
            logger.debug(f"[*] Determined {python_artifact.name} type to be {type_}")
            break
        except TypeError:
            logger.debug(f"[*] Magic incorrect for type {type_}")
    else:
        # This should never be reached
        logger.debug("[!] No artifact types found! Something went wrong. Please submit a bug report.")

    if type_instance:
        type_instance.unpack()


def run(args_in: List[str] = None) -> None:
    """Orchestrate the flow of the pydecipher command.

    This function is the entry-point of the pydecipher command.  It calls out to
    other routines and generally attempts to follow this high-level flow:

        1.  Parse program arguments.
        2.  Check that input files are readable and output locations are
            writeable, including that the the program is running in a
            sufficiently new Python environment (3.6+).
        3.  Recursively call unpack on the artifact until all items of
            interest are extracted.
        4.  Decompile any Python bytecode found through the unpacking
            process.

    Parameters
    ----------
    args_in : List[str]
        If this function is being called from other Python code, pydecipher
        flags and other command-line options can be passed in as a list.
    """
    if sys.version_info < (3, 8):
        logger.critical("[!] This tool can only be run in Python 3.8 or later.")
        sys.exit(1)
    utils.check_for_our_xdis()

    args: argparse.Namespace = _parse_args(args_in)

    logging_options: Dict[str, Union[bool, os.PathLike]] = {"verbose": args.verbose, "quiet": args.quiet}
    pydecipher.set_logging_options(**logging_options)

    artifact_path: pathlib.Path = pathlib.Path(args.artifact_path).resolve()
    utils.check_read_access(artifact_path)

    relocate_pys: bool = False
    pyc_files: Iterable[os.PathLike] = []
    if args.output:
        output_dir: pathlib.Path = pathlib.Path(args.output.strip()).resolve()
        if artifact_path.is_dir():
            relocate_pys = True
    elif artifact_path.is_dir():
        output_dir = artifact_path
        relocate_pys = True
    else:
        output_dir: pathlib.Path = (
            pathlib.Path.cwd() / f"pydecipher_output_{utils.slugify(artifact_path.name.split('.')[0])}"
        )

    if artifact_path.is_file() and os.path.splitext(artifact_path)[1].lower() in (".pyc", ".pyo"):
        relocate_pys = True
        pyc_files = [artifact_path]

    # The following block sets up logging to a stringIO stream, which will
    # eventually be placed in a file. We don't immediately log to a file
    # because we don't want to leave a log file on disk unless the program
    # succeeds, at least past the 'unpack' call.
    log_stream: io.StringIO = io.StringIO()
    log_stream__handler: logging.StreamHandler = logging.StreamHandler(log_stream)
    log_stream__handler.setFormatter(pydecipher.log_format)
    log_stream__handler.setLevel(logging.DEBUG)
    logger.addHandler(log_stream__handler)

    version_hint: str = args.version_hint

    alternate_opmap: Dict[str, int] = None
    if args.remapping_file:
        remap_file: pathlib.Path = pathlib.Path(args.remapping_file).resolve()
        logger.info(f"[*] Using remap file {remap_file}")
        utils.check_read_access(remap_file)
        alternate_opmap: Dict[str, int] = bytecode.create_opmap_from_file(remap_file)

        with remap_file.open("r") as remapping_file:
            file_json: str = json.loads(remapping_file.read())
            remap_file_version: str = file_json["python_version"]
            version_hint = remap_file_version

    utils.check_write_access(output_dir)
    # Dump all pyc files
    if artifact_path.is_dir():
        kwargs: Dict[str, str] = {"version_hint": version_hint}
        dirpath: str
        dirnames: List[str]
        filenames: List[str]
        for (dirpath, dirnames, filenames) in os.walk(artifact_path):
            filename: str
            for filename in filenames:
                if os.path.splitext(filename)[1].lower() in (".pyc", ".pyo"):
                    full_path: pathlib.Path = pathlib.Path(dirpath).joinpath(filename)
                    try:
                        pyc_class_obj: artifact_types.pyc.Pyc = artifact_types.pyc.Pyc(
                            full_path, output_dir=full_path.parent, **kwargs
                        )
                    except TypeError:
                        pass
                    else:
                        pyc_class_obj.unpack()
        pyc_files: List[pathlib.Path] = list(artifact_path.rglob("*.[pP][yY][cCoO]"))
    else:
        unpack(artifact_path, output_dir=str(output_dir), version_hint=version_hint)

    # If we produced files, we want to also include the logged output of
    # pydecipher. If we didn't produce anything, we can assume the program
    # failed/had uninteresting output that doesn't need to be kept. The one
    # exception to this is when we pass in a single pyc file, or a directory of
    # pyc files, to be decompiled.
    if (output_dir.exists() and os.listdir(output_dir)) or pyc_files:
        output_dir.mkdir(parents=True, exist_ok=True)
        log_name: str = datetime.datetime.now().strftime("log_%H_%M_%S_%b_%d_%Y.txt")
        with output_dir.joinpath(log_name).open("w") as log_file_ptr:
            log_file_ptr.write(log_stream.getvalue())
        logging_options: Dict[str, pathlib.Path] = {"log_path": output_dir.joinpath(log_name)}
        pydecipher.set_logging_options(**logging_options)
    else:
        logger.warning("[!] This artifact produced no additional output.")
        return

    # Determine which pyc files to decompile
    if not pyc_files:
        pyc_files: Generator[os.PathLike, None, None] = output_dir.rglob("*.[pP][yY][cCoO]")
        if not args.decompile_all:
            max_depth: int = 10
            # Search output directory with increasing recursive depth to find
            # first level of directories with .pyc files
            depth: int
            for depth in range(max_depth):
                tmp: List[os.PathLike] = list(pydecipher.utils.rglob_limit_depth(output_dir, "*.[pP][yY][cCoO]", depth))
                if tmp:
                    pyc_files = tmp
                    break

    # Dispatch a pool of processes to decompile the specified group of pyc files
    bytecode.process_pycs(pyc_files, alternate_opmap=alternate_opmap)

    # If any decompiled python needs to be moved to the output directory, do
    # that now. This will only happen if the user passed in a pyc artifact
    # (single file or dir). We decompile the .pyc file into a .py file alongside
    # the .pyc file on disk, then move it to the designated output directory.
    if artifact_path.is_file():
        relative_root: pathlib.Path = artifact_path.parent
    else:
        relative_root: pathlib.Path = artifact_path
    if relocate_pys:
        pyc_file: pathlib.Path
        for pyc_file in pyc_files:
            py_file: pathlib.Path = pathlib.Path(str(pyc_file)[:-1])
            if not py_file.exists():
                continue
            rel_path: pathlib.Path = py_file.relative_to(relative_root)
            new_filepath: pathlib.Path = output_dir.joinpath(rel_path)
            py_file.rename(new_filepath)

    # Perform any cleanup functions on output of decompilation
    pydecipher.artifact_types.py2exe.PYTHONSCRIPT.cleanup(output_dir)


if __name__ == "__main__":
    run()
