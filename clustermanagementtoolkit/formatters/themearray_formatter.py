# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A Pygments formatter that outputs to ThemeArray.
"""

from collections.abc import Callable, Generator
import io
from typing import Any

from pygments.formatter import Formatter

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.colorschemes import ColorSchemeEntry


# pylint: disable-next=too-many-instance-attributes
class ThemeArrayFormatter(Formatter):
    """
    A formatter for Pygments that implements support for outputting ThemeArrays.
    """
    # These are initialized in __init__ to avoid complexities with None.
    # buffer: list[list[ThemeRef | ThemeStr]] = None
    # colorscheme: dict[str, ColorSchemeEntry] = None
    # override_formatting: dict[str, ThemeAttr] = None
    # unknown_ttypes: set[Any] = None
    latest_key: str = ""
    lexer: Any | None = None
    renderer: Callable | None = None
    use_github_alerts: bool = False

    def __init__(self, **options: Any):
        Formatter.__init__(self, **options)
        self.colorscheme: dict[str, ColorSchemeEntry] = \
            deep_get(options, DictPath("colorscheme"), {})
        self.override_formatting: dict[str, ThemeAttr] = \
            deep_get(options, DictPath("override_formatting"), {})
        self.lexer = deep_get(options, DictPath("lexer"))
        self.renderer = deep_get(options, DictPath("renderer"))
        self.use_github_alerts = deep_get(options, DictPath("use_github_alerts"), False)
        self.buffer: list[list[ThemeRef | ThemeStr]] = []
        self.unknown_ttypes: set[Any] = set()

    # pylint: disable-next=too-many-locals
    def format(self, tokensource: Generator, outfile: io.StringIO) -> None:
        # Flush the buffer
        self.buffer = []
        self.latest_key = ""

        line: list[ThemeRef | ThemeStr] = []

        for ttype, value in tokensource:
            flush = False

            if self.renderer:
                ttype, value, flush = self.renderer(ttype, value,
                                                    use_github_alerts=self.use_github_alerts)
            if isinstance(value, list) and value and isinstance(value[0], (ThemeRef, ThemeStr)):
                line += value
                if flush:
                    self.buffer.append(line)
                    line = []
                continue
            # Use this when adding new formatters; we can ignore empty strings.
            if ttype not in self.colorscheme \
                    and ttype not in self.unknown_ttypes and value:  # pragma: nocover
                tmpvalue = value
                tmpvalue = tmpvalue.replace('\\', r'<backslash>')
                tmpvalue = tmpvalue.replace(r'"', r'\\\"')
                tmpvalue = tmpvalue.replace('\r', r'\\\r')
                tmpvalue = tmpvalue.replace('\t', r'\\\t')
                tmpvalue = tmpvalue.replace('\b', r'\\\b')
                tmpvalue = tmpvalue.replace('\f', r'\\\f')
                tmpvalue = tmpvalue.replace('<backslash>', r'\\\\')
                # We don't want multiple lines in the error log.
                tmpvalue2 = tmpvalue.split("\n", maxsplit=1)[0]
                errmsg = [
                    [("Encountered unknown token type ", "default"),
                     (f'{ttype}', "argument"),
                     (" for substring starting with “", "default"),
                     (f'{tmpvalue2}', "argument"),
                     ("“ when formatting using lexer ", "default"),
                     (f'{self.lexer!s}', "argument")]
                ]
                unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                self.unknown_ttypes.add(ttype)
            splitlines = value.split("\n")
            formatting_entry = self.colorscheme.get(ttype, {
                "formatting": ThemeAttr("main", "default"),
                "type": "generic",
            })

            formatting = deep_get(formatting_entry,
                                  DictPath("formatting"), ThemeAttr("main", "default"))
            value_type = deep_get(formatting_entry,
                                  DictPath("type"), "generic")
            if "__all" in self.override_formatting:
                formatting = deep_get(self.override_formatting, DictPath("__all"), formatting)
            elif value_type == "key":
                self.latest_key = value
                formatting = deep_get(self.override_formatting,
                                      DictPath(f"{self.latest_key}#key"), formatting)
            elif value_type == "value" and self.latest_key:
                formatting = deep_get(self.override_formatting,
                                      DictPath(f"{self.latest_key}#value"), formatting)

            for n, segment in enumerate(splitlines):
                if segment:
                    line.append(ThemeStr(segment, formatting))
                # If there's a segment after this one we need a newline; otherwise
                # this is a segment
                if n + 1 < len(splitlines):
                    self.buffer.append(line)
                    line = []
        if line:
            self.buffer.append(line)
