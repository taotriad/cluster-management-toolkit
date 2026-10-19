# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.format_yaml import format_yaml


def reformat_json(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Given a string representation of JSON, reformat it.

        Parameters:
            lines (str|[str]): A list of strings *or*
                               a string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [passthrough to format_yaml]
        Returns:
            ([themearray]): A list of themearrays
    """
    kwargs["json"] = True
    return format_yaml(lines, **kwargs)
