# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

try:
    from pygments.lexers.rego import RegoLexer
    REGOLEXER_AVAILABLE = True
except ModuleNotFoundError:
    # RegoLexer is available from Pygments 2.19
    REGOLEXER_AVAILABLE = False

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_REGO
from clustermanagementtoolkit.formatters.format_none import format_none
from clustermanagementtoolkit.formatters.format_pygments_generic import format_pygments_generic


def format_rego(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Rego formatter; returns the text with syntax highlighting for the Rego policy language.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [passthrough to format_pygments_generic]
        Returns:
            list[themearray]: A list of themearrays
    """
    if REGOLEXER_AVAILABLE:
        return format_pygments_generic(lines, **kwargs,
                                       lexer=RegoLexer(),
                                       colorscheme=COLORSCHEME_REGO)
    return format_none(lines)
