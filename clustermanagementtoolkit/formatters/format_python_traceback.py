# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Formatter for Python tracebacks.
"""

from typing import Any

from pygments.lexers.python import PythonTracebackLexer

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_PYTHON_TRACEBACK
from clustermanagementtoolkit.formatters.format_pygments_generic import format_pygments_generic


def format_python_traceback(lines: str | list[str],
                            **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Python Traceback formatter; returns the text with syntax highlighting for Python Tracebacks.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [passthrough to format_pygments_generic]
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=PythonTracebackLexer(),
                                   colorscheme=COLORSCHEME_PYTHON_TRACEBACK)
