# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Print a formatted string.
"""

import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint.ansithemestr import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint.ansithemearray_to_str import ansithemearray_to_str
from clustermanagementtoolkit.ansithemeprint.theme import get_theme, get_themepath

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


def ansithemeprint(themearray: list[ANSIThemeStr], **kwargs: Any) -> None:
    """
    Print a themearray;
    a themearray is a list of format strings of the format:
    (string, theme_attr_ref); context is implicitly understood to be term.

        Parameters:
            themearray ([ANSIThemeStr]): The themearray to print
            **kwargs (dict[str, Any]): Keyword arguments
                stderr (bool): True to print to stderr, False to print to stdout
                color (str):
                    "always": Always use ANSI-formatting
                    "never": Never use ANSI-formatting
                    "auto": Use ANSI-formatting except when redirected
        Raises:
            ProgrammingError: Function called without initializing ansithemestr
    """
    stderr: bool = deep_get(kwargs, DictPath("stderr"), False)
    color: str = deep_get(kwargs, DictPath("color"), "auto")

    use_color = None

    if not get_theme() or get_themepath() is None:
        raise ProgrammingError("ansithemeprint() used without calling init_ansithemeprint() first; "
                               "this is a programming error.")

    match color:
        case "auto":
            if stderr:
                use_color = sys.stderr.isatty()
            else:
                use_color = sys.stdout.isatty()
        case "always":
            use_color = True
        case "never":
            use_color = False
        case _:
            raise ValueError("Incorrect value for color passed to ansithemeprint(); "
                             "the only valid values are ”always”, ”auto”, and ”never”; "
                             "this is a programming error.")

    string = ansithemearray_to_str(themearray, color=use_color)

    if stderr:
        print(string, file=sys.stderr)
    else:
        print(string)
