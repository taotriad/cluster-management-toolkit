# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert ANSIThemeArray to a printable string.
"""

from typing import Any, cast

from clustermanagementtoolkit.ansithemeprint.ansithemestr import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint.theme import get_theme, get_themepath

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


def ansithemearray_to_str(themearray: str | list[ANSIThemeStr] | list[list[ANSIThemeStr]],
                          **kwargs: Any) -> str:
    """
    Convert an ANSIThemeArray ([ANSIThemeStr]) or [ANSIThemeArray] ([[ANSIThemeStr]]) to a string,
    conditionally with ANSI-formatting.

        Parameters:
            themearray ([ANSIThemeStr]|[[ANSIThemeStr]]): The array to strip formatting from
            **kwargs (dict[str, Any]): Keyword arguments
                color (bool): True to emit ANSI-formatting, False to output a plain string
        Returns:
            (str): The string
        Raises:
            ProgrammingError: Function called without initializing ansithemestr
    """
    color: str = deep_get(kwargs, DictPath("color"), "auto")

    if not get_theme() or get_themepath() is None:
        raise ProgrammingError("ansithemearray_to_str() used without calling "
                               "init_ansithemestr() first; this is a programming error.")
    string: str = ""

    if isinstance(themearray, str):
        return themearray

    if themearray and isinstance(themearray[0], ANSIThemeStr):
        themearray = [themearray]
    themearray = cast(list[list[ANSIThemeStr]], themearray)

    strings: list[str] = []

    for themerow in themearray:
        string = ""
        for themestring in themerow:
            if not isinstance(themestring, ANSIThemeStr):
                raise TypeError("ansithemearray_to_str() only accepts arrays of ANSIThemeStr; "
                                f"this themearray consists of:\n{themearray}")

            theme_attr_ref = themestring.themeref
            theme_string = str(themestring)

            if get_theme() and color:
                if theme_attr_ref in get_theme()["term"]:
                    attr = get_theme()["term"][theme_attr_ref]
                    reset = get_theme()["term"]["reset"]
                    string += f"{attr}{theme_string}{reset}"
                else:
                    raise KeyError(f"attribute (\"term\", \"{theme_attr_ref}\") "
                                   f"does not exist in {get_themepath()}")
            else:
                string += theme_string

        if string:
            string = string.replace("\x0033", "\033")
        strings.append(string)

    return "\n".join(strings)
