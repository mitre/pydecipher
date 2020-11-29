# -*- coding: utf-8 -*-
"""Utility functions that help with the creation or manipulation of compiled Python files and Python bytecode.

Attributes
----------
REMAPPED_OPCODE_ERROR_REGEX : re.Pattern
    A regex pattern that matches the uncompyle6 error typically seen when trying
    to decompile Python bytecode that has had its opcodes remapped.
"""
import io
import json
import os
import pathlib
import re
import struct
import sys
from concurrent.futures import TimeoutError
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from types import CodeType, ModuleType
from typing import Any, Dict, Iterable, List, TextIO, Tuple, Union

import pebble
import uncompyle6
import xdis
from xdis import iscode
from xdis.magics import magicint2version

import pydecipher
from pydecipher import logger

__all__ = [
    "REMAPPED_OPCODE_ERROR_REGEX",
    "version_str_to_magic_num_int",
    "create_pyc_header",
    "process_pycs",
    "decompile_pyc",
    "diff_opcode",
    "create_opmap_from_file",
    "validate_opmap",
]

REMAPPED_OPCODE_ERROR_REGEX = re.compile("Parse error at or near .+ instruction at offset [0-9]+$")


def version_str_to_magic_num_int(version_str: str) -> int:
    """Given a Python version string, return it's magic integer.

    Parameters
    ----------
    version_str : str
       Typically a string like '2.7' or '3.8.1'. However, the version string
       can be `any version accepted by xdis`_, including some weird alternate
       Python implementations like 2.7.1b3Jython or 3.5pypy.

       .. _any version accepted by xdis:
           https://github.com/rocky/python-xdis/blob/master/xdis/magics.py

    Returns
    -------
    int
       The magic number corresponding to the version string.
    """
    return xdis.magics.magic2int(xdis.magics.by_version[version_str])


def create_pyc_header(magic_int: int, compilation_ts: Union[int, datetime] = None, file_size: int = 0) -> bytes:
    """Return the header bytes necessary for creation of a compiled Python file.

    Parameters
    ----------
    magic_int : int
        The Python magic number that should be used in the header. This is also
        used to determine the Python version for which the header is being
        created, and consequently, the length and format of the header.
    compilation_ts : Union[int, datetime], optional
        The compilation timestamp (if any) to put in the header.
    file_size : int, optional
        The size of the source code, mod 2^32, to put in the header.

    Returns
    -------
    bytes
        The 8, 12, or 16 bytes of the header, depending on the compiled version
        for which the header was created.
    """
    version: float = float(magicint2version[magic_int][:3])
    header_bytes: bytes = b""
    if version >= 3.3:
        header_bytes += struct.pack("<Hcc", magic_int, b"\r", b"\n")
        if version >= 3.7:  # pep552 bytes
            header_bytes += struct.pack("<I", 0)  # pep552 bytes
    else:
        header_bytes += struct.pack("<Hcc", magic_int, b"\r", b"\n")

    if compilation_ts:
        if isinstance(compilation_ts, datetime):
            header_bytes += struct.pack("<I", int(compilation_ts.timestamp()))
        elif isinstance(compilation_ts, int):
            header_bytes += struct.pack("<I", compilation_ts)
    else:
        header_bytes += struct.pack("<I", int(datetime.now().timestamp()))

    if version >= 3.3:
        # In Python 3.3+, these bytes are the size of the source code (mod 2^32)
        header_bytes += struct.pack("<I", file_size)
    return header_bytes


def process_pycs(pyc_iterable: Iterable[os.PathLike], alternate_opmap: Dict[str, int] = None) -> None:
    """Multi-processed decompilation orchestration of compiled Python files.

    Currently, pydecipher uses `uncompyle6`_ as its decompiler. It works well
    with `xdis`_ (same author) and allows for the decompilation of Code objects
    using alternate opmaps (with our extension of xdis).

    This function will start up CPU count * 2 pydecipher processes to decompile
    the given Python. Attempts to check for debugger, in which case the
    decompilation will be single-threaded to make debugging easier.

    .. _uncompyle6: https://github.com/rocky/python-uncompyle6/
    .. _xdis: https://github.com/rocky/python-xdis

    Parameters
    ----------
    pyc_iterable : Iterable[os.PathLike]
        An iterable of pathlib.Path objects, referencing compiled Python files
        to decompile.
    alternate_opmap : Dict[str, int], optional
        An opcode map of OPNAME: OPCODE (i.e. 'POP_TOP': 1). This should be a
        complete opmap for the Python version of the files being decompiled.
        Even if only two opcodes were swapped, the opcode map passed in should
        contain all 100+ Python bytecode operations.
    """
    # This checks if the PyCharm debugger is attached.
    if sys.gettrace():
        # Single-threaded for easier debugging.
        logger.debug("[!] Debugger detected, not using multiprocessing for decompilation of pyc files.")
        return_status_codes: List[str] = []
        pyc_file: pathlib.Path
        for pyc_file in pyc_iterable:
            return_status_codes.append(decompile_pyc((pyc_file, alternate_opmap, pydecipher.get_logging_options())))
    else:
        return_status_codes: List[str] = []
        pool: pebble.ProcessPool
        with pebble.ProcessPool(os.cpu_count() * 2) as pool:
            iterables = [(pyc, alternate_opmap, pydecipher.get_logging_options()) for pyc in pyc_iterable]
            future: pebble.ProcessMapFuture = pool.map(decompile_pyc, iterables, timeout=300)
            iterator: Iterable = future.result()
            index: int = 0
            while True:
                try:
                    result: Any = next(iterator)
                    return_status_codes.append(result)
                except StopIteration:
                    break
                except TimeoutError as e:
                    e: TimeoutError
                    failed_pyc_path: str = str(iterables[index][0])
                    logger.error(f"[!] Timed out ({e.args[1]}s) trying to decompile {failed_pyc_path}.")
                    return_status_codes.append("error")
                except pebble.ProcessExpired as e:
                    e: pebble.ProcessExpired
                    logger.error(
                        f"[!] Failed to decompile {failed_pyc_path} (process expired with status code {e.exitcode}."
                    )
                    return_status_codes.append("error")
                except Exception as e:
                    e: Exception
                    logger.error(f"[!] Failed to decompile {failed_pyc_path} with unknown error: {e}")
                    return_status_codes.append("error")
                finally:
                    index += 1

    successes: int = return_status_codes.count("success")
    opcode_errors: int = return_status_codes.count("opcode_error")
    errors: int = return_status_codes.count("error") + opcode_errors
    if opcode_errors:
        logger.warning(
            f"[!] {opcode_errors} file(s) failed to decompile with an error "
            "that indicate its opcode mappings may have been remapped. Try using"
            "`remap` on this set of bytecode."
        )
    if successes and not errors:
        logger.info(f"[+] Successfully decompiled {successes} .pyc files.")
    elif successes and errors:
        logger.warning(
            f"[!] Successfully decompiled {successes} .pyc files. Failed to decompile {errors} files. "
            "See log for more information."
        )
    elif not successes and errors:
        logger.error(f"[!] Failed to decompile all {errors} .pyc files. See log for more information.")
    else:
        logger.warning("[!] No pyc files were decompiled. See log for more information.")


def decompile_pyc(arg_tuple: Tuple[pathlib.Path, Dict[str, int], Dict[str, Union[bool, os.PathLike]]]) -> str:
    """Decompile a single Python bytecode file.

    Parameters
    ----------
    arg_tuple: Tuple[pathlib.Path, Dict[str, int], Dict[str, Union[bool, os.PathLike]]]
        A tuple containing the arguments for this function. This is a tuple because pebble's
        Pool.map() function couldn't pass multiple arguments to a subprocessed function call.
        The tuple entries correspond to the following arguments:

            pyc_file : pathlib.Path
                The path to the compiled Python file
            alternate_opmap : Dict[str, int], optional
                If this bytecode file was produced by an interpreter with remapped
                opcodes, you must provide the opmap as a OPNAME: OPCODE dictionary
            logging_options: Dict[str, Union[bool, os.PathLike], optional
                A dictionary of logging options. This is only needed when pydecipher is
                performing multi-processed decompilation. The keys can be the following
                strings:

                    verbose: bool
                        True will enable verbose logging.
                    quiet: bool
                        True will silence all console logging.
                    log_path: pathlib.Path
                        If a path object is passed in as the log_path, the running
                        instance of pydecipher will continue logging to that file.

    Returns
    -------
    str
        There are several different return values:

            * **no_action**: This file was not decompiled.
            * **success**: This file was successfully decompiled.
            * **error**: This file could not be decompiled 100% successfully.
            * **opcode_error**: The error message returned by uncompyle6
              indicates this file may have remapped opcodes
    """
    pyc_file: pathlib.Path = arg_tuple[0]
    alternate_opmap: Dict[str, int] = arg_tuple[1] or None
    logging_options: Dict[str, Union[bool, os.PathLike]] = arg_tuple[2] or None

    if not pyc_file.is_file():
        return "no_action"

    # Because this function runs in a new pydecipher process entirely, logging
    # options set during runtime (from command-line flags) do not carry over
    # automatically. We must pass these through manually, and reset the options
    # for this specific process.
    if logging_options and not pydecipher.log_path:
        pydecipher.set_logging_options(**logging_options)

    hijacked_stdout: io.StringIO = io.StringIO()
    hijacked_stderr: io.StringIO = io.StringIO()
    with redirect_stdout(hijacked_stdout), redirect_stderr(hijacked_stderr):
        # Chop off c in pyc
        new_file_name: pathlib.Path = pathlib.Path(str(pyc_file.resolve())[:-1])

        # This prohibits the overwriting of existing files.
        # if new_file_name.exists() and new_file_name.stat().st_size:
        #     return "no_action"

        logger.debug(f"[*] Decompiling file {pyc_file} of size {pyc_file.stat().st_size}")
        if not alternate_opmap:
            try:
                uncompyle6.decompile_file(str(pyc_file), outstream=sys.stdout)
            except uncompyle6.semantics.parser_error.ParserError as e:
                logger.warning(f"[!] Failed to decompile file {pyc_file}")
                if REMAPPED_OPCODE_ERROR_REGEX.match(str(e.error)):
                    logger.error(
                        f"[!] {pyc_file.name} failed to decompile with an error that indicate its opcode "
                        "mappings may have been remapped to prevent analysis."
                    )
                    return "opcode_error"
                return "error"
            except Exception as e:
                e: Exception
                logger.error(f"[!] Failed to decompile file {pyc_file} with error: {e}")
                stdout_val: str = hijacked_stdout.getvalue()
                if stdout_val:
                    with new_file_name.open("w") as file_ptr:
                        file_ptr.write(stdout_val)
                return "error"
            else:
                with new_file_name.open("w") as file_ptr:
                    file_ptr.write(hijacked_stdout.getvalue())
                logger.info(f"[+] Successfully decompiled {pyc_file}")
                return "success"
        else:
            filename: str
            co: CodeType  # can also be xdis.Code* objects
            version: float
            timestamp: int  # seconds since epoch
            magic_int: int
            is_pypy: bool
            source_size: int
            sip_hash: str
            try:
                (
                    filename,
                    co,
                    version,
                    timestamp,
                    magic_int,
                    is_pypy,
                    source_size,
                    sip_hash,
                ) = xdis.disasm.disassemble_file(
                    str(pyc_file), outstream=open(os.devnull, "w"), alternate_opmap=alternate_opmap
                )
                output_file: TextIO
                with new_file_name.open(mode="w") as output_file:
                    uncompyle6.main.decompile(
                        version,
                        co,
                        timestamp=timestamp,
                        source_size=source_size,
                        magic_int=magic_int,
                        is_pypy=is_pypy,
                        out=output_file,
                    )
            except Exception as e:
                e: Exception
                logger.info(f"[!] Failed to decompile file {pyc_file} with error: {e}")
                return "error"
            else:
                logger.info(f"[+] Successfully decompiled {pyc_file}")
            return "success"


def diff_opcode(code_standard: CodeType, code_remapped: CodeType, version: str = None) -> Dict[int, Dict[int, int]]:
    """Calculate remapped opcodes from two Code objects of the same sourcecode.

    Parameters
    ----------
    code_standard : Code (xdis.CodeX or types.CodeType)
        The standard-opcode Code object
    code_remapped : Code (xdis.CodeX or types.CodeType)
        The remapped-opcode Code object
    version : str, optional
        The Python version that marshaled the former two arguments. Used for
        figuring out what operations push arguments to the stack.

    Returns
    -------
    Dict[int, Dict[int, int]]
        A dictionary of original_opcode to
        Dict[replacement_opcode:replacement_count]. replacement_opcode is an
        opcode that was seen in place of original_opcode, and the
        replacement_count is the amount of times it was seen replacing the
        original_opcode throughout all the bytecode that was analyzed.

    Raises
    ------
    RuntimeError
        Args aren't correct type or differ in total opcode count too much.
    """

    def _recursively_extract_all_code_objects(co) -> List[bytes]:
        """Co is a code object, with potentially nested code objects."""
        co_code_objects: List[bytes] = [co.co_code]
        search_list: List[Union[Any]] = list(co.co_consts)
        co_obj: Any
        for co_obj in search_list:
            if iscode(co_obj):
                if co_obj not in co_code_objects:
                    co_code_objects.append(co_obj.co_code)
                    search_list.extend(co_obj.co_consts)
        return co_code_objects

    def _build_opcode_index(co_code_objects, HAVE_ARGUMENT=90, version: str = None) -> List[int]:
        """Build a list of opcodes contained within the list of co_code objects."""
        # Helpful for learning about opcode + arg length:
        # https://laike9m.com/blog/demystifying-extended_arg,124/
        if iscode(co_code_objects):
            co_code_objects: List[bytes] = [co_code_objects]
        opcode_index: List[int] = []
        co_code: bytes
        for co_code in co_code_objects:
            i: int = 0
            while i < len(co_code):
                incrementer: int = 1
                opcode: int = co_code[i]
                if opcode >= HAVE_ARGUMENT:
                    incrementer = 3
                opcode_index.append(opcode)
                if version and float(version[:3]) >= 3.6:
                    # After 3.6 all opcodes are two bytes, and the second byte
                    # is empty if the opcode doesn't take an argument.
                    incrementer = 2
                i += incrementer
        return opcode_index

    if not iscode(code_standard) or not iscode(code_remapped):
        raise RuntimeError("diff_opcode requires two Code objects as arguments")

    HAVE_ARGUMENT: int = 90
    if version:
        try:
            xdis_opcode: ModuleType = xdis.disasm.get_opcode(version, is_pypy=("pypy" in version))
        except TypeError:
            logger.warning("[!] Couldn't retrieve version {version}'s opcodes from xdis.")
        else:
            HAVE_ARGUMENT = xdis_opcode.HAVE_ARGUMENT

    standard_code_objects: List[bytes] = _recursively_extract_all_code_objects(code_standard)
    remapped_code_objects: List[bytes] = _recursively_extract_all_code_objects(code_remapped)
    standard_opcodes_list: List[int] = _build_opcode_index(standard_code_objects, HAVE_ARGUMENT, version=version)
    remapped_opcodes_list: List[int] = _build_opcode_index(remapped_code_objects, HAVE_ARGUMENT, version=version)

    if abs(len(standard_opcodes_list) - len(remapped_opcodes_list)):
        # This is to prevent cases where files are being compared that don't
        # share source code
        raise RuntimeError(
            "The two co_code objects differ in length and therefore cannot do a comparison of the opcodes."
        )

    i: int
    remappings: Dict[int, Dict[int, int]] = {}
    for i, remapped_opcode in enumerate(remapped_opcodes_list):
        if standard_opcodes_list[i] in remappings:
            existing_remap_options: Dict[int, int] = remappings[standard_opcodes_list[i]]
            if remapped_opcode in existing_remap_options:
                existing_remap_options[remapped_opcode] += 1
            else:
                existing_remap_options[remapped_opcode] = 1
        else:
            remappings[standard_opcodes_list[i]] = {remapped_opcode: 1}
    return remappings


def create_opmap_from_file(file_path: os.PathLike) -> Dict[str, int]:
    """Return an opcode map dictionary of OPNAME : OPCODE from a JSON file.

    The JSON file must enumerate a complete opmap for the specified Python
    version. Even if only a few bytes have been swapped, all operations and
    opcodes must have a value for the version specified.

    Parameters
    ----------
    file_path : os.PathLike
        The path to the JSON remapping file. This file *must* follow this
        format.

        .. code-block::

            {
                "python_version": "<major>.<minor>(.<patch>)",
                "remapped_opcodes": [
                    {
                        "opcode": 1,
                        "opname": "POP_TOP",
                        "remapped_value": 5
                    },
                    {
                        "opcode": 2,
                        "opname": "ROT_TWO",
                        "remapped_value": 4
                    },
                    ...

    Returns
    -------
    Dict[str, int]
        A dictionary of OPNAME : OPCODE. For example::

        {
            'POP_TOP': 5,
            'ROT_TWO': 4,
            ...
        }
    """
    if not file_path.exists():
        raise FileNotFoundError(file_path)

    remappings: Dict[str, int] = {}
    with file_path.open("r") as remapping_file:
        file_json: str = json.loads(remapping_file.read())
        version: str = file_json["python_version"]
        subdict: Dict[str, Union[str, int]]
        for subdict in file_json["remapped_opcodes"]:
            remappings[subdict["opname"]] = subdict["remapped_value"]

    if not validate_opmap(version, remappings):
        raise RuntimeError("[!] Opcode map is not valid!")
    return remappings


def validate_opmap(version: str, opmap: Dict[str, int]) -> bool:
    """Validate whether opmap is correct/well-formed for the given version.

    A well-formed opcode map should not have any duplicate keys or values, nor
    any missing or extraneous opnames or opcodes.

    Parameters
    ----------
    version : str
        Typically a string like '2.7' or '3.8.1'. However, the version string
        can be `any version accepted by xdis`_, including some weird alternate
        Python implementations like 2.7.1b3Jython or 3.5pypy.

        .. _any version accepted by xdis:
            https://github.com/rocky/python-xdis/blob/master/xdis/magics.py
    opmap : Dict[str, int]
        A dictionary of OPERATION NAME: OPCODE VALUE.

    Returns
    -------
    bool
        Whether or not this opcode map is valid and well-formed.

    """
    is_pypy: bool = True if "pypy" in version else False
    try:
        opcode_obj: ModuleType = xdis.disasm.get_opcode(version, is_pypy)
    except KeyError:
        raise KeyError(f"[!] The version specified, {version}, is not supported by xdis.")
    xdis_opcode_map: Dict[str, int] = opcode_obj.opmap
    validity: bool = True

    opname: str
    opcode: int
    for opname, opcode in opmap.items():
        if opname not in xdis_opcode_map.keys():
            logger.debug(
                f"[!] This opcode map contains the opname {opname}, which doesn't appear to be a valid "
                f"operation for Python {version}."
            )
            validity = False
        if list(opmap.keys()).count(opname) > 1:
            logger.debug(
                f"[!] This opcode map contains {list(opmap.keys()).count(opname)} entries for the opname {opname}."
            )
            validity = False
        if list(opmap.values()).count(opcode) > 1:
            logger.debug(
                f"[!] This opcode map contains {list(opmap.values()).count(opcode)} entries for the opcode {opcode}."
            )
            validity = False

    for opname, opcode in xdis_opcode_map.items():
        if opname not in opmap.keys():
            logger.debug(
                f"[!] This opcode map does not have an entry for the opname {opname}. In standard Python "
                f"{version}, this value is {opcode}."
            )
            validity = False

    if len(opmap.keys()) != len(xdis_opcode_map.keys()):
        logger.debug(
            f"[!] This opcode map has a size of {len(opmap.keys())}, when it should have a size of "
            f"{len(xdis_opcode_map.keys())} for Python version {version}."
        )
        validity = False

    return validity
