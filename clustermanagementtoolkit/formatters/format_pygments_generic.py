# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

import pygments

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.themearray_formatter import ThemeArrayFormatter
from clustermanagementtoolkit.formatters.format_none import format_none

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def format_pygments_generic(lines: str | list[str], **kwargs: Any) -> \
        list[list[ThemeRef | ThemeStr]]:
    """
    Generic formatter; returns the text with syntax highlighting.

        Parameters:
            lines (str|[str]|dict): A list of strings *or*
                               a string with newlines that should be split,
                               *or* a dict to dump as yaml
            **kwargs (dict[str, Any]): Keyword arguments
                raw (bool): Show raw document instead of formatting it
                lexer (pygments.lexer): A pygments lexer
                colorscheme (dict[Any, ColorSchemeEntry]): A mapping from a token
                                                           to a formatting dict
                formatter (callable): The formatter to use when outputting the data
        Returns:
            ([themearray]): A list of themearrays
    """
    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, list):
        lines = "\n".join(lines)

    lexer = deep_get(kwargs, DictPath("lexer"))
    colorscheme = deep_get(kwargs, DictPath("colorscheme"))
    formatter = ThemeArrayFormatter(colorscheme=colorscheme, lexer=lexer)
    pygments.highlight(lines, lexer, formatter)

    return formatter.buffer
