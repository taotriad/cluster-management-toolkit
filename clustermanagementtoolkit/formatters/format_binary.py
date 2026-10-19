# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


# pylint: disable-next=unused-argument
def format_binary(lines: bytes, **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Binary "formatter"; Just returns a message saying that binary views cannot be viewed.

        Parameters:
            lines (bytes): [unused]
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([themearray]): A list of themearrays
    """
    return [[ThemeStr("Binary file; cannot view", ThemeAttr("types", "generic"))]]
