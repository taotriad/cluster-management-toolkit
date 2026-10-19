# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from pygments.lexers.shell import BashLexer

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_SHELLSCRIPT
from clustermanagementtoolkit.formatters.format_pygments_generic import format_pygments_generic


def format_shellscript(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Shell script formatter; returns the text with syntax highlighting for shell scripts.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [passthrough to format_pygments_generic]
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=BashLexer(),
                                   colorscheme=COLORSCHEME_SHELLSCRIPT)
