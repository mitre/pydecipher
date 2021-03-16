# -*- coding: utf-8 -*-
"""Distutils setup information for pydecipher."""
import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

doc_requires = ["sphinx", "sphinx_rtd_theme", "towncrier"]

test_requires = [
    "pytest",
    "dataclasses",
]

dev_requires = (
    doc_requires
    + test_requires
    + ["bump2version", "black", "pre-commit", "flake8", "flake8-docstrings", "restructuredtext-lint"]
)

EXTRAS = {
    "dev": dev_requires,
    "docs": doc_requires,
    "test": test_requires,
}

setuptools.setup(
    name="pydecipher",
    version="1.0.0",
    author="The MITRE Corporation",
    author_email="pydecipher@mitre.org",
    description="Python un-freezing and bytecode extraction + analysis framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mitre/pydecipher",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: Software Development :: Code Generators",
        "Topic :: Software Development :: Disassemblers",
    ],
    install_requires=[
        "xdis>=5.0.8",
        "python-magic",
        "argparse",
        "six",
        "pefile",
        "uncompyle6",
        "signify>=0.3.0",
        "asn1crypto",
        "pycrypto",
        "textdistance",
        "Pebble",
    ],
    extras_require=EXTRAS,
    entry_points={
        "console_scripts": ["pydecipher=pydecipher.main:run", "melt=pydecipher.main:run", "remap=pydecipher.remap:run"],
    },
)
