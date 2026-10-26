# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Print a prompt and wait for a password input.
"""

import errno
import getpass
import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint.ansithemestr import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint.ansithemearray_to_str import ansithemearray_to_str
from clustermanagementtoolkit.ansithemeprint.theme import get_theme, get_themepath

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


def ansithemeinput_password(themearray: list[ANSIThemeStr], **kwargs: Any) -> str:
    """
    Print a themearray and input a password;
    a themearray is a list of format strings of the format:
    (string, theme_attr_ref); context is implicitly understood to be term.

        Parameters:
            themearray ([(str, str)]): The themearray to print
        Returns:
            string (str): The inputted password
            **kwargs (dict[str, Any]): Keyword arguments
                color (str):
                    "always": Always use ANSI-formatting
                    "never": Never use ANSI-formatting
                    "auto": Use ANSI-formatting except when redirected
        Raises:
            ProgrammingError: Function called without initializing ansithemestr
    """
    color: str = deep_get(kwargs, DictPath("color"), "auto")

    use_color = None

    if not get_theme() or get_themepath() is None:
        raise ProgrammingError("ansithemeinput_password() used without calling "
                               "init_ansithemeprint() first; this is a programming error.")

    match color:
        case "auto":
            use_color = sys.stdout.isatty()
        case "always":
            use_color = True
        case "never":
            use_color = False
        case _:
            raise ValueError("Incorrect value for color passed to ansithemeinput_password(); "
                             "the only valid values are ”always”, ”auto”, and ”never”; "
                             "this is a programming error.")

    string = ansithemearray_to_str(themearray, color=use_color)
    try:
        tmp = getpass.getpass(string)
    except KeyboardInterrupt:  # pragma: no cover
        print()
        sys.exit(errno.ECANCELED)
    return tmp.replace("\x00", "<NUL>")
