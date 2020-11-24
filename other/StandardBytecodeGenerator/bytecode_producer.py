#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Download, compile, and transfer the standard library files in CPython.

Meant to be run from within a ubuntu-based docker container with pyenv
installed. Build instructions as follows:

docker build . -t pydecipher/sbg   # context is the dockerfile + this script
docker run --volume "$(pwd):/bc" pydecipher/sbg 2.7.15

Dumps all the bytecode to the containers /bc directory, so that must be mapped
back to the host. Somewhat capable of detecting shorthand version strings (i.e.
converting 2.7 to 2.7.18, so pyenv can download a real version)
"""
import argparse
import pathlib
import re
import subprocess
import sys
import os
from typing import List
import shutil

pyenv_root = pathlib.Path(os.environ.get("PYENV_ROOT"))
bytecode_dump_dir = pathlib.Path(os.environ.get("BYTECODE_DUMP_DIR"))


def find_latest_installable_patch_version(version_str: str) -> str:
    """Take a major.minor version and finds its latest patch version.

    Parameters
    ----------
    version_str: str
        The version string (i.e. 2.7, 3.7 etc)

    Returns
    -------
    str
        The latest major.minor.patch version pyenv has for the given version
    """
    all_versions: List[str] = find_installable_versions()
    patch_versions: List[str] = []
    version: str
    for version in all_versions:
        if version.startswith(version_str) and re.match(r"^[1-3](?:\.[0-9]{1,2}){2}$", version):
            patch_versions.append(version)

    # this is a weird version (miniconda/pypy/etc) or has no patches
    if not patch_versions:
        return version_str

    highest_patch: int = 0
    pv: str
    for pv in patch_versions:
        patch_num: int = int(pv[pv.rfind(".") + 1 :])
        if patch_num > highest_patch:
            highest_patch = patch_num

    return f"{version_str}.{highest_patch}"


def find_installed_versions() -> List[str]:
    """Return a list of all the versions pyenv has currently installed.

    Returns
    -------
    List[str]
        All of the versions currently installed in pyenv
    """
    versions_dir: pathlib.Path = pyenv_root / "versions"
    return os.listdir(versions_dir)


def find_installable_versions() -> List[str]:
    """Return a list of all the versions pyenv can install.

    Uses the output of the `pyenv install --list` command.

    Returns
    -------
    List[str]
        All of the versions pyenv is capable of installing.
    """
    pyenv_install_output: bytes = subprocess.check_output(["pyenv", "install", "--list"])
    pyenv_versions: List[str] = pyenv_install_output.decode().split("\n")[1:]
    pyenv_versions = [x.strip() for x in pyenv_versions if x]  # removes empty strings
    return pyenv_versions


def install_version(version: str):
    """
    Install a given version of Python in pyenv.

    Runs `pyenv install <version>` and exits if it fails

    Parameters
    ----------
    version: str
        The version of Python to install

    Returns
    -------
    subprocess.Popen.returncode
        The return code of the installation subprocess that installed the Python version
    """
    ret_val: subprocess.Popen.returncode = subprocess.call(["pyenv", "install", version])
    if ret_val:
        print(f"Install of version {version} failed.")
        sys.exit(1)
    else:
        print(f"pyenv successfully installed version {version}")


def extract_pyc_files(source_dir: pathlib.Path) -> int:
    """
    Transfer all compiled python files in source_dir to /bc in the container.

    Parameters
    ----------
    source_dir: pathlib.Path
        The source directory of the Python installation for which you want all the compiled Python files.

    Returns
    -------
    int
        The number of files transferred.
    """
    destination_dir = bytecode_dump_dir

    counter = 0
    for pyc_file in source_dir.rglob("*.pyc"):
        new_dest = destination_dir.joinpath(pyc_file.relative_to(source_dir.parent))
        new_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pyc_file, new_dest)
        counter += 1
    return counter


def main():
    """
    Entrypoint for script.

    Expects a single argument in sys.argv.
    """
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument("version", type=str, help="python version you want the bytecode for")
    args = parser.parse_args()
    version_str = args.version.strip()
    print(f"version_str: {version_str}")

    # Matches 2.7 but not 2.7.17
    version_match_obj = re.match(r"^[1-3](?:\.[0-9]{1,2})$", version_str)

    if version_str not in find_installable_versions():
        print(f"Version {version_str} doesn't appear to be a valid version that pyenv can install")
        sys.exit(1)
    else:
        if version_match_obj and version_match_obj.group().count(".") < 2:
            # major.minor version given, which is incompatible with pyenv
            # need to specify patch version as well
            version = find_latest_installable_patch_version(version_match_obj.group())
        else:
            version = version_str

        if version not in find_installed_versions():
            print(f"Version {version} not installed in this environment! Installing now...")
            install_version(version)

    source_dir = pyenv_root / "versions" / version
    count = extract_pyc_files(source_dir)
    print(f"Successfully moved {count} files to the destination directory.")


if __name__ == "__main__":
    main()
