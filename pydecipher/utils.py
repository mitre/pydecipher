# -*- coding: utf-8 -*-
"""General utility functions that may be useful across the module."""
import os
import pathlib
import re
import string
import sys
import unicodedata
from typing import Generator, List, Set, Tuple

import xdis

from pydecipher import logger

__all__ = [
    "slugify",
    "parse_for_strings",
    "parse_for_version_strings",
    "rglob_limit_depth",
    "check_read_access",
    "check_write_access",
    "check_for_our_xdis",
]


def slugify(value: str, allow_unicode: bool = False) -> str:
    """Take a string and remove any potentially 'problematic' characters.

    Note
    ----
        This function is `taken from Django's codebase`_.

    Converts a string to a URL slug by:

    #. Converting to ASCII if allow_unicode is False (the default).
    #. Removing characters that aren’t alphanumerics, underscores, hyphens, or
       whitespace.
    #. Removing leading and trailing whitespace.
    #. Converting to lowercase.
    #. Replacing any whitespace or repeated dashes with single dashes.

    .. _taken from Django's codebase:
        https://github.com/django/django/blob/stable/3.0.x/django/utils/text.py#L393

    Parameters
    ----------
    value: str
        The string to be converted
    allow_unicode: bool
        Whether or not to allow unicode characters.

    Returns
    -------
    str
        The cleaned string.
    """
    value: str = str(value)
    if allow_unicode:
        value = unicodedata.normalize("NFKC", value)
    else:
        value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def parse_for_strings(data: bytes) -> Set[str]:
    """Given a blob of data, will return a set of all the readable/printable strings.

    Parameters
    ----------
    data: bytes
        The data to search for printable strings.

    Returns
    -------
    Set[str]
        A set of the printable strings in this data.

    """
    strings: set = set()
    current_string: str = ""
    byte: bytes
    for byte in bytearray(data):
        try:
            char: str = chr(byte)
            if char not in string.printable:
                raise ValueError
            current_string += char
        except ValueError:
            if current_string:
                strings.add(current_string)
            current_string = ""
    if current_string:
        strings.add(current_string)
    return strings


def parse_for_version_strings(data: bytes, formats=[r"[0-9](?:\.[0-9]+)+", "(?<=(python))[0-9]{2}"]) -> List[str]:
    """Search for Python version numbers within a blob of data.

    Parameters
    ----------
    data: bytes
        The data to search for version strings.

    Returns
    -------
    List[Tuple[str, str]]
        The Python versions found, along with the the strings that contain those version
        numbers. Format is (version_number, string_that_contained_version_number).
    """
    data_utf8: str = data.decode("utf-8", "ignore")
    data_utf16: str = data.decode("utf-16", "ignore")
    data: str = data_utf8 + data_utf16

    matches: List[Tuple[str, str]] = []
    fmt: str
    for fmt in formats:
        match_indices: List[Tuple[str, Tuple[int, int]]] = [
            (m.group(), m.span()) for m in re.finditer(fmt, data, re.IGNORECASE)
        ]
        # This builds a list of the following format:
        #   [
        #       ('match1', (match_1_start_index, match_1_end_index)),
        #       ('match2', (match_2_start_index, match_2_end_index)),
        #       ('match3', (match_3_start_index, match_3_end_index))...
        #   ]
        #  The indices are integers indexing where the matches were found in the
        #  datastream.
        match_tuple: Tuple[str, Tuple[int, int]]
        for match_tuple in match_indices:
            match: str = match_tuple[0]
            start_idx: int = match_tuple[1][0]
            end_idx: int = match_tuple[1][1]

            # Maximum amount of bytes we should give surrounding each match
            surrounding_bytes_length: int = 50
            lower_limit: int = start_idx
            higher_limit: int = end_idx
            i: int
            for i in range(1, surrounding_bytes_length):
                if data[start_idx - i] in string.printable:
                    lower_limit = start_idx - i
                else:
                    break
            for i in range(1, surrounding_bytes_length):
                if data[end_idx + i] in string.printable:
                    higher_limit = end_idx + i
                else:
                    break
            surrounding_bytes: str = data[lower_limit:higher_limit]
            matches.append((match, surrounding_bytes))

    valid_matches: List[Tuple[str, str]] = []
    match_bytes_tuple: Tuple[str, str]
    for match_bytes_tuple in matches:
        match: str = match_bytes_tuple[0]
        if len(match) == 2 and match.isnumeric():
            # makes 27 -> 2.7
            match = f"{match[0]}.{match[1]}"
        if match not in xdis.magics.canonic_python_version.keys():
            continue
        valid_matches.append(match_bytes_tuple)

    valid_matches = list(set(valid_matches))  # unique-ifies this list
    valid_matches.sort(key=lambda x: x[0])  # sort by increasing version number
    return valid_matches


def rglob_limit_depth(path_obj: pathlib.Path, pattern: str, n: int = 1) -> Generator[os.PathLike, None, None]:
    """Path object rglob, but allows for limit to depth of recursive search.

    Parameters
    ----------
    path_obj: pathlib.Path
        The path to recursively search for the pattern.
    pattern: str
        The pattern to search for.
    n: int
        The maximum recursive depth.

    Yields
    ------
    pathlib.Path
        A path matching the given pattern.
    """
    baseline_path_depth: int = len(list(path_obj.parents))
    p: pathlib.Path
    for p in path_obj.rglob(pattern):
        if len(p.parents) <= (baseline_path_depth + n):
            yield p


def check_read_access(path: pathlib.Path) -> None:
    """Verify that we can read successfully from the given file path.

    Parameters
    ----------
    path: os.PathLike
        The path to check.
    """
    if not path.exists():
        msg: str = f"[!] Could not find the provided path: {str(path)}."
        raise FileNotFoundError(msg)
    if not os.access(path, os.R_OK):
        msg: str = f"[!] Lacking read permissions on: {str(path)}."
        raise PermissionError(msg)


def check_write_access(path: pathlib.Path) -> None:
    """Verify that we can write successfully to the given file path.

    Parameters
    ----------
    path: pathlib.Path
        The path to check.
    """
    if not path.parent.exists():
        msg: str = "[!] Parent of output directory does not exist. Cannot write here."
        raise NotADirectoryError(msg)
    if not os.access(path.parent, os.W_OK):
        msg: str = f"[!] Cannot write output directory to dir: {str(path)}."
        raise PermissionError(msg)


def check_for_our_xdis() -> None:
    """Check that the pydecipher fork of xdis is installed.

    Exits if its not.
    """
    if hasattr(xdis.op_imports, "remap_opcodes"):
        logger.debug("[*] Custom version of xdis detected. All clear to proceed.")
    else:
        logger.error(
            "[!] It seems that the public/normal version of xdis has been installed. Please see the documentation"
            "on how to download the pydecipher-customized fork of xdis."
        )
        sys.exit(1)
