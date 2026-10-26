# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Join multiple strings into one formatted string, optionally adding separators.
"""

from typing import Any
from collections.abc import Sequence

from clustermanagementtoolkit.ansithemeprint.ansithemestr import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import deep_get, DictPath


def ansithemestr_join_list(items: Sequence[str | ANSIThemeStr],
                           **kwargs: Any) -> list[ANSIThemeStr]:
    """
    Given a list of ANSIThemeStrs or strings + formatting, join them separated by a separator.

        Parameters:
            items ([str | ANSIThemeStr]): The items to join into an ANSIThemeStr list
            **kwargs (dict[str, Any]): Keyword arguments
                formatting (str): The formatting to use if the list is a string-list
                separator (ANSIThemeStr): The list separator to use
        Return:
            themearray ([ANSIThemeStr]): The resulting ANSIThemeStr list
    """
    formatting: str = deep_get(kwargs, DictPath("formatting"), "default")
    if "separator" in kwargs:
        separator: ANSIThemeStr | None = deep_get(kwargs, DictPath("separator"))
    else:
        separator = ANSIThemeStr(", ", "separator")

    themearray = []
    first = True

    for item in items:
        if isinstance(item, str):
            tmpitem = ANSIThemeStr(item, formatting)
        else:
            tmpitem = item

        if not first:
            if separator is not None:
                themearray.append(separator)
        else:
            first = False
        themearray.append(tmpitem)

    return themearray
