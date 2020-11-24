# -*- coding: utf-8 -*-
import os
import pathlib

__all__ = []

# We import all the modules here because we need the @register decorator
# in each artifact_type module to run during pydecipher's initial loading. If the
# decorator didn't run, the unpack() function will not be able to detect that specific
# artifact type.
_this_file_path: pathlib.Path = pathlib.Path(__file__)
_file: str
for _file in os.listdir(_this_file_path.parent):
    if _file.endswith(".py") and _file != _this_file_path.name:
        __all__.append(os.path.splitext(_file)[0])

from . import *  # noqa
