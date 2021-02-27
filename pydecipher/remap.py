# -*- coding: utf-8 -*-
"""Contains the functionality for the ``remap`` command.

remap takes in Python bytecode that has been compiled using non-standard (remapped) opcodes, and attempts to detect the
new opmap key value pairings. The output of remap is a JSON file with information about the new opmap.
"""
import argparse
import copy
import datetime
import io
import json
import logging
import os
import pathlib
import sys
import tempfile
from types import CodeType, ModuleType
from typing import Any, BinaryIO, Dict, List, Set, TextIO, Tuple, Union

import textdistance
import xdis

import pydecipher
from pydecipher import artifact_types, bytecode, logger, utils

__all__ = [
    "_parse_args",
    "write_remapping_file",
    "fix_remapping_conflicts",
    "fill_opmap_gaps",
    "megafile_remap",
    "opcode_constants_remap",
    "standard_pyc_remap",
    "run",
]


def _parse_args(_args: List = None) -> argparse.Namespace:
    """Parse remap's arguments and accordingly set run-time options.

    Usually these arguments will come from the command line, however if
    remap is being called from code, `args` may be passed in as a list.

    Parameters
    ----------
    _args : List, optional
        A list of arguments/flags. If you are calling remap from code,
        you need to pass in your command line as a space-delimited list.
        i.e. for ``remap --megafile 2.7 all.pyx``, args would be
        ['--megafile', '2.7', 'all.pyx'].

    Returns
    -------
    argparse.Namespace
      The populated namespace of options for remap's runtime.
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="remap", description="Recreate opmaps from modified Python bytecode."
    )
    parser.add_argument("remapped_bytecode_path", type=str, help="Path to remapped Python bytecode")
    parser.add_argument(
        "--version",
        type=str,
        help="The version of Python used to compile the bytecode (versions must be supported by xdis)",
    )
    remap_method = parser.add_mutually_exclusive_group()
    remap_method.add_argument(
        "-m",
        "--megafile",
        required=False,
        help=(
            "The input is the standard compiled version of your megafile, or a megafile version that remap natively"
            " supports (Currently only 2.7)."
        ),
    )
    remap_method.add_argument(
        "--opcode-file",
        action="store_true",
        required=False,
        help="The input is a compiled instance of opcode.py.",
    )
    remap_method.add_argument(
        "-s",
        "--standard-bytecode-path",
        type=str,
        required=False,
        help="Path to standard Python bytecode",
    )
    remap_method.add_argument(
        "-c",
        "--check-remapping",
        action="store_true",
        help="Check the validity and support for the specified remapping file.",
    )
    output_settings: Any = parser.add_mutually_exclusive_group()
    output_settings.add_argument("-q", "--quiet", action="store_true", help="Suppress all stdout/err output")
    output_settings.add_argument("-v", "--verbose", action="store_true", help="Show verbose output")
    parser.add_argument(
        "-o",
        "--output",
        required=False,
        help="Location for the remap_output_* directory (defaults to current working directory)",
    )
    return parser.parse_args(_args)


def write_remapping_file(
    remappings: Dict[int, Tuple[int, bool]],
    version: str,
    method: str,
    cli: str,
    output_dir: Union[str, pathlib.Path] = ".",
) -> pathlib.Path:
    """Write the remappings dict to a JSON file that can be used by pydecipher.

    It is assumed that by this point `remappings` is a bijection of original
    opcodes and replacement opcodes.

    Parameters
    ----------
    remappings: Dict[int, (int, bool)]
        A dictionary of original_opcode to (replacement_opcode, guess).
        replacement_opcode is the remapped value of original_opcode, and the
        guess boolean is whether or not remap actually observed this remapping
        or had to 'guess' it in order to produce a complete set of opcodes.
    version: str
        A version string `accepted by xdis`_.
    output_dir: Union[str, os.PathLike]
        The path where the remapping file should be written.
    method: str
        A text description of the remapping method used
    cli: str
        The command line for the remap command that produced this file.

        .. _accepted by xdis:
            https://github.com/rocky/python-xdis/blob/master/xdis/magics.py

    Returns
    -------
    pathlib.Path
        The path to the remapping JSON file.
    """
    output_dict: Dict[str : Union[int, Dict[int, int]]] = {
        "python_version": str(version),
        "remapped_opcodes": [],
        "method": method,
        "command_line": json.dumps(cli),
    }

    xdis_opcode: ModuleType = None
    try:
        xdis_opcode = xdis.disasm.get_opcode(version, is_pypy=False)
    except Exception:
        logger.debug(f"[!] Couldn't retrieve version {version} from xdis! Continuing anyway...")

    opcode_val: int
    remapping_dict: Dict[int, int]
    for opcode_val, remap_val in remappings.items():
        output_subdict: Dict[str, int] = {
            "opcode": opcode_val,
            "remapped_value": remap_val[0],
            "guess": True if remap_val[1] else False,
        }
        if xdis_opcode:
            opname: str = xdis_opcode.opname[opcode_val]
            output_subdict["opname"] = opname.replace("+", "_")
        output_dict["remapped_opcodes"].append(output_subdict)

    # We sort based on the original opcode value because it seems like the most
    # natural way to sort this, and it is useful to have a standardized
    # output for comparison purposes.
    output_dict["remapped_opcodes"] = sorted(output_dict["remapped_opcodes"], key=lambda i: i["opcode"])
    output_dir: pathlib.Path = pathlib.Path(output_dir).resolve()
    output_filepath: pathlib.Path = output_dir / "remapping.txt"
    if output_filepath.exists():
        logger.debug(
            f"[!] {str(output_filepath)} already exists. Incrementing filename until an available name is found."
        )
        counter: int = 1
        while True:
            new_filepath: pathlib.Path = output_dir / f"remapping-{counter}.txt"
            if not new_filepath.exists():
                break
            counter += 1
        output_filepath = new_filepath
    output_dir.mkdir(parents=True, exist_ok=True)
    with output_filepath.open("w") as output_file_ptr:
        output_file_ptr.write(json.dumps(output_dict, sort_keys=True, indent=4))
        logger.info(f"[+] {str(output_filepath)} successfully written")
    return output_filepath


def fix_remapping_conflicts(remappings: Dict[int, Dict[int, int]]) -> Dict[int, int]:
    """Remove conflicting remappings from the remappings dictionary.

    For example, say part of the remappings dict is ::

        { 1 : { 5 : 4779
                27 : 1},
        ....
          24 : { 27 : 204 },
        ...
        }

    It is way more likely that 24 was remapped to 27 rather than 1 being
    remapped to 27. The single instance that 27 was seen in place of 1 was likely
    just noise, compared to the 204 times 27 was seen replacing 24.

    This function removes those duplicates and ensures the dictionary returned
    has one-to-one relationships.

    Parameters
    ----------
    remappings: Dict[int, Dict[int, int]]
        A dictionary of original_opcode to
        Dict[replacement_opcode:replacement_count]. replacement_opcode is
        an opcode that was seen in place of original_opcode, and the
        replacement_count is the amount of times it was seen replacing the
        original_opcode throughout all the bytecode that was analyzed.

    Returns
    -------
    Dict[int, int]
        A dictionary of original_opcode to replacement_opcode, with no
        duplicates or conflicts.

    Raises
    ------
    RuntimeError
        An opcode not in the known valid range of opcodes was found in this opmap.
    """
    # This dict is a flipped version of remappings. The key is the remapped
    # value, and the value (tuple) is the opcode that has the `best` claim
    # for being the original opcode for that key (its replacement count).
    new_opcode_dict: Dict[int, Tuple[int, int]] = {}

    original_opcode: int
    remap_options: Dict[int, int]
    for original_opcode, remap_options in remappings.items():
        # Purpose of this loop is to build out new_opcode_dict.
        # If two opcodes map to the same value, the one with the more
        # replacements gets it.
        if original_opcode < 0 or original_opcode > 255:
            raise RuntimeError(f"Found opcode {original_opcode} in remappings. Opcodes must be in range 0 to 255.")

        remap_option: int
        count: int
        for remap_option, count in remap_options.items():
            if (remap_option in new_opcode_dict) and (count < new_opcode_dict[remap_option][1]):
                # If this remapping already has a potential 'original opcode,'
                # and has a worse 'claim' (lower replacement count), we ignore
                # it.
                continue
            else:
                new_opcode_dict[remap_option] = (original_opcode, count)

    validated_remappings: Dict[int, int] = {v[0]: k for k, v in new_opcode_dict.items()}
    return validated_remappings


def fill_opmap_gaps(remappings: Dict[int, int], version: str) -> Dict[int, Tuple[int, bool]]:
    """Fill the opmap with any missing opcodes for a specific version.

    Since pydecipher can only take in a valid opmap, we must make sure remap
    dumps opmaps that contain complete sets of opcodes. Very rarely will an
    opcode remapping method be able to cover 100% of opcodes in use for a
    particular Python version, so we need to fill the gaps with some guesses.

    Parameters
    ----------
    remappings: Dict[int, int]
        A dictionary of original opcode to remapped opcode.
    version: str
        A version string `accepted by xdis`_.

        .. _accepted by xdis:
            https://github.com/rocky/python-xdis/blob/master/xdis/magics.py

    Returns
    -------
    Dict[int, Tuple[int, bool]]
        A dictionary of original opcode to remapped opcode and a boolean indicating
        whether or not this remapping was guessed or observed.
    """
    filled_remappings: Dict[int, Tuple[int, bool]] = {k: (v, False) for k, v in remappings.items()}
    is_pypy: bool = True if "pypy" in version else False
    try:
        opcode_obj: ModuleType = xdis.disasm.get_opcode(version, is_pypy)
    except KeyError:
        raise KeyError(f"[!] The version specified, {version}, is not supported by xdis.")
    xdis_opcode_map: Dict[str, int] = opcode_obj.opmap
    xdis_opcode_vals: Set[int] = set(xdis_opcode_map.values())
    remaining_options: List[int] = list(xdis_opcode_vals.difference(set(remappings.values())))
    logger.debug(f"[*] Set of opcodes available to assign from standard opmap: {remaining_options}")
    missing_opcodes = list(xdis_opcode_vals.difference(set(remappings.keys())))
    logger.debug(f"[*] Set of opcodes that need an assignment in the modified opmap: {missing_opcodes}")

    missing_opcode: int
    for missing_opcode in missing_opcodes:
        smallest_distance: int = 999
        best_option: int = -1
        option: int
        for option in remaining_options:
            distance: int = abs(option - missing_opcode)
            if distance < smallest_distance:
                best_option = option
                smallest_distance = distance
        filled_remappings[missing_opcode] = (best_option, True)
        remaining_options.remove(best_option)

    return filled_remappings


def megafile_remap(
    reference_megafile: pathlib.Path, remapped_bytecode_path: pathlib.Path
) -> Tuple[Dict[int, Dict[int, int]], str]:
    """Calculate the remapped opcodes and version of a megafile.

    This takes in the standard-compiled version of the megafile, as well as
    the custom-interpreter version. It returns the Python version and the
    dictionary of opcodes to possible remapped opcodes.

    Parameters
    ----------
    reference_megafile: pathlib.Path
        The standard-compiled version of the megafile.
    remapped_bytecode_path: pathlib.Path
        The custom-interpreter version of the megafile.

    Returns
    -------
     Tuple[Dict[int, Dict[int, int]], str]
        A tuple containing a dictionary of original_opcode to
        Dict[replacement_opcode:replacement_count] and the opmap's Python
        version. replacement_opcode is an opcode that was seen in place of
        original_opcode, and the replacement_count is the amount of times it was
        seen replacing the original_opcode throughout all the bytecode that was
        analyzed.
    """
    reference_filename: str
    reference_co: CodeType  # can also be xdis codetypes
    reference_version: float
    reference_timestamp: int
    reference_magic_int: int
    reference_is_pypy: bool
    reference_source_size: int
    reference_sip_hash: str
    (
        reference_filename,
        reference_co,
        reference_version,
        reference_timestamp,
        reference_magic_int,
        reference_is_pypy,
        reference_source_size,
        reference_sip_hash,
    ) = xdis.disasm.disassemble_file(str(reference_megafile), outstream=open(os.devnull, "w"))

    fixed_megafile_file: pathlib.Path
    if fixed_megafile_file := artifact_types.pyc.Pyc.check_and_fix_pyc(
        remapped_bytecode_path, provided_version=str(reference_version)
    ):
        logger.error(
            f"[+] Duplicated megafile file {str(remapped_bytecode_path)} to correct issues with the pyc. New filepath:"
            f" {fixed_megafile_file.name}"
        )
        remapped_bytecode_path = fixed_megafile_file.name

    try:
        remapped_filename: str
        remapped_co: CodeType  # can also be xdis codetypes
        remapped_version: float
        remapped_timestamp: int
        remapped_magic_int: int
        remapped_is_pypy: bool
        remapped_source_size: int
        remapped_sip_hash: str
        (
            remapped_filename,
            remapped_co,
            remapped_version,
            remapped_timestamp,
            remapped_magic_int,
            remapped_is_pypy,
            remapped_source_size,
            remapped_sip_hash,
        ) = xdis.disasm.disassemble_file(str(remapped_bytecode_path), outstream=open(os.devnull, "w"))
    except Exception as e:
        e: Exception
        logger.debug(f"Error disassembling remap megafile: {e}")
        logger.debug(
            "It is possible that this custom interpreter has tampered with the Python code compilation process in such"
            " a way that xdis cannot disassemble it. You can try manually inspecting the file to learn more."
        )
        raise RuntimeError

    remappings: Dict[int, Dict[int, int]] = bytecode.diff_opcode(reference_co, remapped_co, str(reference_version))
    return remappings, str(reference_version)


def opcode_constants_remap(
    opcode_file: pathlib.Path, provided_version: str = None
) -> Tuple[Dict[int, Dict[int, int]], str]:
    """Parse code object constants to try and recreate opcode mappings.

    This method walks the constants attribute of the opcode.pyc code object.
    See the remap documentation for more information on this method.

    Parameters
    ----------
    opcode_file: pathlib.Path
        The path on disk to the opcode.pyc file.
    provided_version: str, optional
        The version of Python that this opcode file corresponds to.

    Returns
    -------
     Tuple[Dict[int, Dict[int, int]], str]
        A tuple containing a dictionary of original_opcode to
        Dict[replacement_opcode:replacement_count] and the opmap's Python
        version. replacement_opcode is an opcode that was seen in place of
        original_opcode, and the replacement_count is the amount of times it was
        seen replacing the original_opcode throughout all the bytecode that was
        analyzed.
    """

    def get_nearest_opcode(opname: str, unused_opcodes: List[int], version: str) -> int:
        xdis_opcode: ModuleType
        try:
            xdis_opcode = xdis.disasm.get_opcode(version, is_pypy=False)
            actual_opcode = getattr(xdis_opcode, opname)
        except Exception:
            return unused_opcodes[0]

        smallest_distance: int = 999
        closest_opcode: int = -1
        for opcode in unused_opcodes:
            if abs(actual_opcode - opcode) < smallest_distance:
                closest_opcode = opcode
                smallest_distance = abs(actual_opcode - opcode)
        return closest_opcode

    logger.debug(f"[*] Checking opcode.pyc file at {str(opcode_file)} to determine if opcode map is normal.")
    fixed_pyc_file: tempfile.NamedTemporaryFile
    if fixed_pyc_file := artifact_types.pyc.Pyc.check_and_fix_pyc(opcode_file, provided_version=provided_version):
        logger.error(
            f"[+] Duplicated opcode file {str(opcode_file)} to correct issues with the pyc. New filepath:"
            f" {fixed_pyc_file.name}"
        )
        opcode_file = fixed_pyc_file.name

    filename: str
    co: CodeType  # can also be xdis.Code* objects
    version: float
    timestamp: int  # seconds since epoch
    magic_int: int
    is_pypy: bool
    source_size: int
    sip_hash: str
    try:
        (filename, co, version, timestamp, magic_int, is_pypy, source_size, sip_hash) = xdis.disasm.disassemble_file(
            str(opcode_file), header=True, outstream=open(os.devnull, "w")
        )
    except Exception as e:
        e: Exception
        logger.error(f"[!] Couldn't disassemble opcode file {opcode_file} with error: {e}")
        raise e

    built_opmap: Dict[str, int] = {}

    unused_opnames: List[str] = []  # opnames seen in the co_consts list not next to an integer
    unused_opcodes: List[int] = []  # opcodes seen in the co_consts list not after a string (opname)
    ignore_list: List[Union[str, int]] = [
        "HAVE_ARGUMENT",
        "BAD",
        256,
    ]  # known constants that are not part of the opmap yet appear in the co_consts attribute

    # Go through constants list in disassembly and try to recreate opmap
    i: int = 0
    while i < len(co.co_consts):
        constant: Any = co.co_consts[i]
        if isinstance(constant, str) and constant not in ignore_list:
            constant = constant.replace("+", "_")  # + signs will trip up below `if`
            if constant.isupper():
                # opname confirmed
                if len(co.co_consts) - 1 > i:
                    # check that we aren't at the end of the consts list
                    if isinstance(co.co_consts[i + 1], int):
                        # check if next item in list is the opcode
                        built_opmap[constant] = co.co_consts[i + 1]
                        i += 2
                    else:
                        if unused_opcodes:
                            opcode = get_nearest_opcode(constant, unused_opcodes, version)
                            unused_opcodes.remove(opcode)
                            built_opmap[constant] = opcode
                        else:
                            unused_opnames.append(constant)

                        i += 1
                        continue
            else:
                i += 1
                continue
        elif isinstance(constant, int) and constant not in ignore_list:
            unused_opcodes.append(constant)
            i += 1
            continue
        else:
            i += 1
            continue

    # add any that were remaining at end of algorithm
    opname: str
    for opname in unused_opnames:
        if unused_opcodes:
            opcode: int = get_nearest_opcode(opname, unused_opcodes, version)
            unused_opcodes.remove(opcode)
            built_opmap[opname] = opcode
        else:
            break

    is_pypy: bool = "pypy" in xdis.magics.magicint2version[magic_int]
    opc: ModuleType = xdis.disasm.get_opcode(version, is_pypy)
    remappings: Dict[int, Dict[int, int]] = {}

    # We need to match the format of the other remappings method's return values
    opname: str
    opval: int
    for opname, opval in built_opmap.items():
        remappings[opc.opmap[opname]] = {opval: 1}
    return remappings, str(version)


def standard_pyc_remap(
    standard_bytecode_path: pathlib.Path, remapped_bytecode_path: pathlib.Path, version: str = None
) -> Tuple[Dict[int, Dict[int, int]], str]:
    """Diff compiled code objects from standard library and modified interpreter to try and recreate opcode mappings.

    This method is similar to the megafile method, but at a larger scale.
    See the remap documentation for more information on this method.

    Parameters
    ----------
    standard_bytecode_path: pathlib.Path
        The path on disk to the reference set of standard-compiled bytecode. The version of Python for the reference set
        must correspond to the version of Python used as a base for the modified interpreter.
    remapped_bytecode_path: pathlib.Path
        The path on disk to the set of bytecode compiled by the modified interpreter
    version: str, optional
        The version of Python that this opcode file corresponds to.

    Returns
    -------
     Tuple[Dict[int, Dict[int, int]], str]
        A tuple containing a dictionary of original_opcode to
        Dict[replacement_opcode:replacement_count] and the opmap's Python
        version. replacement_opcode is an opcode that was seen in place of
        original_opcode, and the replacement_count is the amount of times it was
        seen replacing the original_opcode throughout all the bytecode that was
        analyzed.
    """
    reference_files: Dict[str, List[pathlib.Path]] = {}
    determined_version: str = ""
    pyc_file: pathlib.Path
    for pyc_file in standard_bytecode_path.rglob("*.pyc"):
        pyc_file_name: str = pyc_file.name.split(".")[0]
        if pyc_file_name == "__init__":
            continue
        if not determined_version:
            try:
                infile: BinaryIO
                with pyc_file.open("rb") as infile:
                    pyc_magic_bytes: bytes = infile.read(4)
                    version_set: Set[str] = copy.deepcopy(xdis.magics.by_magic[pyc_magic_bytes])
                    determined_version = version_set.pop()
            except Exception:
                pass
            else:
                logger.debug(f"Determined version {determined_version} from reference bytecode.")
                if version and bytecode.version_str_to_magic_num_int(
                    determined_version
                ) != bytecode.version_str_to_magic_num_int(version):
                    logger.warning(
                        f"Provided version {version} does not equal the version determined in the reference pyc "
                        f"set ({determined_version}). We will proceed with the version you provided."
                    )
        if pyc_file_name in reference_files:
            reference_files[pyc_file_name].append(pyc_file)
        else:
            reference_files[pyc_file_name] = [pyc_file]

    if not version:
        version = determined_version

    remapped_files: Dict[str, List[pathlib.Path]] = {}
    for pyc_file in remapped_bytecode_path.rglob("*"):
        if not pyc_file.is_file():
            continue
        try:
            kwargs: Dict[str, str] = {"version_hint": version}
            artifact_types.pyc.Pyc(pyc_file, **kwargs)
        except TypeError:
            continue
        pyc_file_name: str = pyc_file.name.split(".")[0]
        if pyc_file_name == "__init__":
            # Too common a filename, causes more problems than its worth to try to include these
            # since they are usually empty anyway.
            continue
        if pyc_file_name in remapped_files:
            remapped_files[pyc_file_name].append(pyc_file)
        else:
            remapped_files[pyc_file_name] = [pyc_file]

    master_remapping_counts: Dict[int, Dict[int, int]] = {}
    pyc_filename: str
    list_of_filepaths: List[pathlib.Path]
    for pyc_filename, list_of_filepaths in remapped_files.items():
        if pyc_filename not in reference_files:
            continue
        pyc_filepath: pathlib.Path
        for pyc_filepath in list_of_filepaths:
            reference_file: pathlib.Path = None
            highest_similarity: int = 0
            ref_pyc_filepath: pathlib.Path
            for ref_pyc_filepath in reference_files[pyc_filename]:
                relative_reference_filepath: str = str(ref_pyc_filepath.relative_to(standard_bytecode_path))
                relative_remapped_filepath: str = str(pyc_filepath.relative_to(remapped_bytecode_path))
                path_similarity: float = textdistance.lcsstr.normalized_similarity(
                    relative_reference_filepath, relative_remapped_filepath
                )
                if path_similarity > highest_similarity:
                    highest_similarity = path_similarity
                    reference_file = ref_pyc_filepath
            if not reference_file:
                continue

            fixed_pyc_file: tempfile.NamedTemporaryFile
            if fixed_pyc_file := artifact_types.pyc.Pyc.check_and_fix_pyc(pyc_filepath, provided_version=version):
                logger.debug(
                    f"[+] Duplicated file {str(pyc_filepath)} to correct issues with the pyc. New filepath:"
                    f" {fixed_pyc_file.name}"
                )
                pyc_filepath = fixed_pyc_file.name

            try:
                remapped_filename: str
                remapped_co: CodeType  # can also be xdis codetypes
                remapped_version: float
                remapped_timestamp: int
                remapped_magic_int: int
                remapped_is_pypy: bool
                remapped_source_size: int
                remapped_sip_hash: str
                (
                    remapped_filename,
                    remapped_co,
                    remapped_version,
                    remapped_timestamp,
                    remapped_magic_int,
                    remapped_is_pypy,
                    remapped_source_size,
                    remapped_sip_hash,
                ) = xdis.disasm.disassemble_file(str(pyc_filepath), header=True, outstream=open(os.devnull, "w"))

                reference_filename: str
                reference_co: CodeType  # can also be xdis codetypes
                reference_version: float
                reference_timestamp: int
                reference_magic_int: int
                reference_is_pypy: bool
                reference_source_size: int
                reference_sip_hash: str
                (
                    reference_filename,
                    reference_co,
                    reference_version,
                    reference_timestamp,
                    reference_magic_int,
                    reference_is_pypy,
                    reference_source_size,
                    reference_sip_hash,
                ) = xdis.disasm.disassemble_file(str(reference_file), outstream=open(os.devnull, "w"))
            except Exception:
                continue

            version = str(reference_version)

            try:
                remappings: Dict[int, int] = bytecode.diff_opcode(reference_co, remapped_co, version)
            except RuntimeError:
                continue

            # merge these remappings into the larger dictionary.
            opcode_val: int
            remap_options: Dict[int, int]
            for opcode_val, remap_options in remappings.items():
                if opcode_val in master_remapping_counts:
                    remap_option: int
                    count: int
                    for remap_option, count in remap_options.items():
                        if remap_option in master_remapping_counts[opcode_val]:
                            master_remapping_counts[opcode_val][remap_option] += count
                        else:
                            master_remapping_counts[opcode_val][remap_option] = count
                else:
                    master_remapping_counts[opcode_val] = remap_options

    return master_remapping_counts, version


def run(_args: List[str] = None) -> None:
    """Orchestrate the flow of the remap command.

    This is the entry-point of the remap command. It calls out to other routines
    and attempts to follow this high-level flow:

        1.  Check that program is running in sufficiently new Python
            environment, and parse any arguments
        2.  Determine what type of input was passed to program, which will
            ultimately decide what method remap uses to recover the opmap.
        3.  Attempt one of the opmap recovery methods (see documentation for
            more on these methods)
        4.  If the opmap was successfully recovered, validate it, then write
            it to a file.

    Parameters
    ----------
    _args : List[str]
        If this function is being called from other Python code, remap
        flags and other command-line options can be passed in as a list.
    """
    if sys.version_info < (3, 8):
        logger.critical("[!] This tool can only be run in Python 3.8 or later.")
        sys.exit(1)
    utils.check_for_our_xdis()

    args: argparse.Namespace = _parse_args(_args)

    logging_options: Dict[str, Union[bool, os.PathLike]] = {"verbose": args.verbose, "quiet": args.quiet}
    pydecipher.set_logging_options(**logging_options)

    remapped_bytecode_path: pathlib.Path = pathlib.Path(args.remapped_bytecode_path).resolve()

    if args.output:
        output_dir: pathlib.Path = pathlib.Path(args.output.strip()).resolve()
    else:
        output_dir: pathlib.Path = pathlib.Path.cwd()
    output_dir = output_dir / f"remap_output_{utils.slugify(remapped_bytecode_path.name)}"

    # The following block sets up logging to a stringIO stream, which will
    # eventually be placed in a file. We don't immediately log to a file because
    # we don't want to leave a log file on disk unless the program succeeds.
    log_stream: io.StringIO = io.StringIO()
    log_stream__handler: logging.StreamHandler = logging.StreamHandler(log_stream)
    log_stream__handler.setFormatter(pydecipher.log_format)
    log_stream__handler.setLevel(logging.DEBUG)
    logger.addHandler(log_stream__handler)

    remappings: Dict[int, Dict[int, int]] = {}
    version: str = ""
    remapping_method: str = ""
    cli: str = " ".join(sys.argv) if not _args else " ".join(_args)
    if args.version:
        version = args.version
    if args.megafile:
        # Determine if argument is a version or a path
        if pathlib.Path(args.megafile).exists():
            standard_bytecode_path: pathlib.Path = pathlib.Path(args.megafile)
        else:
            potential_version: str = args.megafile
            magic_num: int = bytecode.version_str_to_magic_num_int(potential_version)
            if magic_num:
                compiled_file: str
                for compiled_file in os.listdir(pathlib.Path(__file__).parent / "reference_files" / "compiled"):
                    full_path_obj: pathlib.Path = (
                        pathlib.Path(__file__).parent / "reference_files" / "compiled" / compiled_file
                    )
                    infile: BinaryIO
                    with full_path_obj.open("rb") as infile:
                        if xdis.magics.magic2int(infile.read(4)) == magic_num:
                            logger.info(f"[*] Found matching megafile for version {potential_version}")
                            standard_bytecode_path: pathlib.Path = full_path_obj
                            break
            if not standard_bytecode_path:
                logger.error(
                    "[!] Something went wrong. remap could not find a standard compiled version of this megafile."
                )  # Next, find the path of the reference file
                sys.exit(1)
        remappings, version = megafile_remap(standard_bytecode_path, remapped_bytecode_path)
        remapping_method = "Megafile"
    elif args.opcode_file:
        remappings, version = opcode_constants_remap(remapped_bytecode_path, provided_version=version)
        remapping_method = "opcode.pyc constants-walking"
    elif args.standard_bytecode_path:
        standard_bytecode_path: pathlib.Path = pathlib.Path(args.standard_bytecode_path).resolve()
        utils.check_read_access(standard_bytecode_path)
        utils.check_read_access(remapped_bytecode_path)
        utils.check_write_access(output_dir)
        if not remapped_bytecode_path.is_dir():
            raise ValueError(
                "The standard/default remapping method requires a directory containing Python bytecode files"
            )
        if not standard_bytecode_path.is_dir():
            raise ValueError(
                "If you are going to provide your own reference opcode set, it must be a directory of "
                "Python bytecode files"
            )
        remappings, version = standard_pyc_remap(standard_bytecode_path, remapped_bytecode_path, version=version)
        remapping_method = "Diff'ing against standard library bytecode"
    elif args.check_remapping:
        # Here, remapped_bytecode_path is not actually bytecode, its a remapping
        # file.
        utils.check_read_access(remapped_bytecode_path)
        remapping_file: TextIO
        with remapped_bytecode_path.open() as remapping_file:
            try:
                remapping_json: Dict["str", Union[str, int]] = json.loads(remapping_file.read())
            except json.decoder.JSONDecodeError as e:
                e: json.decoder.JSONDecodeError
                logger.error(f"Could not read remapping file with error: {e}")
                sys.exit(1)
            version = remapping_json["python_version"]
            remappings_list: Dict[str, Union[bool, str, int]] = remapping_json["remapped_opcodes"]
            remapping_dict: Dict[str, int] = {d["opname"]: d["remapped_value"] for d in remappings_list}
            if bytecode.validate_opmap(version, remapping_dict):
                logger.info("[*] This opmap is valid.")
                return
            else:
                msg: str = "This opmap is not valid."
                if not logging_options["verbose"]:
                    msg += " Run with --verbose flag for more information."
                logger.warning(f"[!] {msg}")
                sys.exit(1)

    if remappings:
        remappings: Dict[int, int] = fix_remapping_conflicts(remappings)
        remappings: Dict[int, Tuple[int, bool]] = fill_opmap_gaps(remappings, version)
        output_file_path: pathlib.Path = write_remapping_file(
            remappings, version, remapping_method, cli, output_dir=output_dir
        )
        logger.info(f"[*] Remapping file {output_file_path.name} written to {output_file_path.parent}.")

        # If we successfully produced the remapping file, we want to also
        # include the logged output of remap.
        log_name: str = datetime.datetime.now().strftime("log_%H_%M_%S_%b_%d_%Y.txt")
        log_file_ptr: TextIO
        with output_dir.joinpath(log_name).open("w") as log_file_ptr:
            log_file_ptr.write(log_stream.getvalue())
        logging_options: Dict[str, Union[bool, os.PathLike]] = {"log_path": output_dir.joinpath(log_name)}
        pydecipher.set_logging_options(**logging_options)
    else:
        logger.warning("[!] Remap couldn't produce the new opmap. Run with --verbose for more information.")
        sys.exit(1)


if __name__ == "__main__":
    run()
