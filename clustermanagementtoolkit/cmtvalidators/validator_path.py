# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate that an argument is a path.
"""

from pathlib import Path
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cmtvalidators.set_programname import get_programname


def validator_path(value: str, **kwargs: Any) -> bool:
    """
    Validate a string to see if it's a valid path.

        Parameters:
            value (str): The string to validate
            **kwargs (dict[str, Any]): Keyword arguments
                error_on_failure (bool): Show an error message on failure
                types ([str]): file and/or dir
        Returns:
            (bool): True if valid, False if invalid
    """
    error_on_failure = deep_get(kwargs, DictPath("error_on_failure"), True)
    types: list[str] = deep_get(kwargs, DictPath("types"), ["file"])
    programname = get_programname()
    pathtype: str = ""
    valid = True

    if Path(value).is_file():
        pathtype = "file"
    elif Path(value).is_dir():
        pathtype = "dir"
    if pathtype not in types:
        valid = False
    if not valid and error_on_failure:
        ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                        ANSIThemeStr(": “", "default"),
                        ANSIThemeStr(f"{value}", "option"),
                        ANSIThemeStr("“ is not a valid path.", "default")], stderr=True)
    return valid
