# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

try:
    from pygments.lexers.cel import CELLexer
    CELLEXER_AVAILABLE = True
except ModuleNotFoundError:
    # CELLexer is available from Pygments 2.21
    CELLEXER_AVAILABLE = False

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_CEL
from clustermanagementtoolkit.formatters.format_none import format_none
from clustermanagementtoolkit.formatters.format_pygments_generic import format_pygments_generic


def format_cel(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    CEL formatter; returns the text with syntax highlighting for Common Expression Language.
    If pygments 2.19.2 or newer is available this will provide syntax highlighting;
    otherwise format_none will be used instead.

        Parameters:
            lines ([str]): A list of strings
            *or*
            lines (str): a string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [passthrough to format_pygments_generic]
        Returns:
            ([themearray]): A list of themearrays
    """
    if CELLEXER_AVAILABLE:
        return format_pygments_generic(lines, **kwargs,
                                       lexer=CELLexer(),
                                       colorscheme=COLORSCHEME_CEL)
    return format_none(lines)
