# -*- coding: utf-8 -*-
"""Sphinx documentation configuration."""
from pydecipher import __version__ as pydecipher_version

# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = "pydecipher"
copyright = "2020, The MITRE Corporation"
author = "The MITRE Corporation"

# The full version, including alpha/beta/rc tags
release = pydecipher_version


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "changes"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]
html_css_files = [
    "css/pydecipher_custom.css",
]

# html_favicon = '_static/img/favicon.ico'
#
# html_logo = "_static/img/logo.png"

# This allows for the use of global-like variables across our documentation
rst_prolog = f"""
.. |Py2Exe| replace:: `Py2Exe <http://www.py2exe.org/>`__
.. |PyInstaller| replace:: `PyInstaller <https://www.pyinstaller.org/>`__
.. |bbFreeze| replace:: `bbFreeze <https://pypi.org/project/bbfreeze/>`__
.. |cx_Freeze| replace:: `cx_Freeze <https://pypi.org/project/cx-Freeze/>`__
.. |py2app| replace:: `py2app <https://pypi.org/project/py2app/>`__
.. |pyinstxtractor| replace:: `pyinstxtractor <https://github.com/countercept/python-exe-unpacker/blob/master/pyinstxtractor.py>`__
.. |pyREtic| replace:: `pyREtic <https://github.com/MyNameIsMeerkat/pyREtic>`__
.. |pydecipher_version| replace:: {pydecipher_version}
.. |towncrier| replace:: `towncrier <https://towncrier.readthedocs.io/en/actual-freaking-docs/index.html>`__
.. |uncompyle6| replace:: `uncompyle6 <https://github.com/rocky/python-uncompyle6>`__
.. |unpy2exe| replace:: `unpy2exe <https://github.com/matiasb/unpy2exe>`__
.. |xdis| replace:: `xdis <https://github.com/rocky/python-xdis>`__
"""


# https://stackoverflow.com/questions/28994795/sphinx-how-do-i-document-all-classes-members-of-a-module-but-not-the-module-its?rq=1
def _remove_module_docstring(app, what, name, obj, options, lines):
    if what == "module" and name.startswith("pydecipher.") and "members" in options:
        del lines[:]


def setup(app):
    """Hack to format documentation the way we want it.

    When viewing the documentation, ideally the order goes as follows:

    1. Module doc string
    2. Restructured text documentation file
    3. Module functions/classes/variables at the end.
    """
    app.connect("autodoc-process-docstring", _remove_module_docstring)
