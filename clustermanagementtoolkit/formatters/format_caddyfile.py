# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

try:
    from pygments.lexers.configs import CaddyfileLexer  # type: ignore[attr-defined,unused-ignore]
    CADDYFILELEXER_AVAILABLE = True
except ImportError:
    # CaddyfileLexer is available from Pygments 2.21
    CADDYFILELEXER_AVAILABLE = False

from clustermanagementtoolkit.cmtlib import split_msg

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_CADDYFILE
from clustermanagementtoolkit.formatters.format_none import format_none
from clustermanagementtoolkit.formatters.format_pygments_generic import format_pygments_generic


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def format_caddyfile(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    CaddyFile formatter; returns the text with syntax highlighting for CaddyFiles.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
                raw (bool): Show raw document instead of rendering the document
        Returns:
            list[themearray]: A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if CADDYFILELEXER_AVAILABLE:
        return format_pygments_generic(lines, **kwargs,
                                       lexer=CaddyfileLexer(),
                                       colorscheme=COLORSCHEME_CADDYFILE)

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    single_site: bool = True
    site: bool = False

    block_open_regex: re.Pattern[str] = re.compile(r"^(\s*)({)(.*)")
    snippet_regex: re.Pattern[str] = re.compile(r"^(\s*)(\(.+?\))(.*)")
    site_regex: re.Pattern[str] = re.compile(r"^(\s*)(\S+?)(\s+{\s*$|$)")
    block_close_regex: re.Pattern[str] = re.compile(r"^(\s*)(}\s*$)")
    matcher_regex: re.Pattern[str] = re.compile(r"^(\s*)(@.*?|\*/.*?)(\s.*)")
    directive_regex: re.Pattern[str] = re.compile(r"^(\s*)(.+?)(\s.*|$)")
    argument_regex: re.Pattern[str] = re.compile(r"^(.*?)(\s{\s*$|$)")

    for line in lines:
        tmpline: list[ThemeRef | ThemeStr] = []

        # Empty line
        if not line and not tmpline:
            tmpline = [
                ThemeStr("", ThemeAttr("types", "generic")),
            ]

        directive = False
        block_depth = 0

        while line:
            # Is this a comment?
            if "#" in line:
                tmpline += [
                    ThemeStr(line, ThemeAttr("types", "caddyfile_comment")),
                ]
                line = ""
                continue

            # Are we opening a block?
            tmp = block_open_regex.match(line)
            if tmp is not None:
                block_depth += 1
                if tmp[1]:
                    tmpline += [
                        ThemeStr(tmp[1], ThemeAttr("types", "caddyfile_block")),
                    ]
                tmpline += [
                    ThemeStr(tmp[2], ThemeAttr("types", "caddyfile_block")),
                ]
                line = tmp[3]
                if site:
                    single_site = False
                continue

            # Is this a snippet?
            tmp = snippet_regex.match(line)
            if tmp is not None:
                if tmp[1]:
                    tmpline += [
                        ThemeStr(tmp[1], ThemeAttr("types", "caddyfile_snippet")),
                    ]
                tmpline += [
                    ThemeStr(tmp[2], ThemeAttr("types", "caddyfile_snippet")),
                ]
                line = tmp[3]
                continue

            # Is this a site?
            tmp = site_regex.match(line)
            if tmp and not block_depth and not site and (single_site or "{" in tmp[3]):
                if tmp[1]:
                    tmpline += [
                        ThemeStr(tmp[1], ThemeAttr("types", "caddyfile_site")),
                    ]
                tmpline += [
                    ThemeStr(tmp[2], ThemeAttr("types", "caddyfile_site")),
                ]
                line = tmp[3]
                site = True
                single_site = False
                continue

            # Are we closing a block?
            tmp = block_close_regex.match(line)
            if tmp is not None:
                block_depth -= 1
                if tmp[1]:
                    tmpline += [
                        ThemeStr(tmp[1], ThemeAttr("types", "caddyfile_block")),
                    ]
                tmpline += [
                    ThemeStr(tmp[2], ThemeAttr("types", "caddyfile_block")),
                ]
                line = ""
                continue

            # Is this a matcher?
            tmp = matcher_regex.match(line)
            if tmp is not None:
                if tmp[1]:
                    tmpline += [
                        ThemeStr(tmp[1], ThemeAttr("types", "caddyfile_matcher")),
                    ]
                tmpline += [
                    ThemeStr(tmp[2], ThemeAttr("types", "caddyfile_matcher")),
                ]
                line = tmp[3]
                continue

            # Is this a directive?
            if not directive:
                tmp = directive_regex.match(line)
                if tmp is not None:
                    if tmp[1]:
                        tmpline += [
                            ThemeStr(tmp[1], ThemeAttr("types", "caddyfile_directive")),
                        ]
                    tmpline += [
                        ThemeStr(tmp[2], ThemeAttr("types", "caddyfile_directive")),
                    ]
                    line = tmp[3]
                    directive = True
                    continue
            else:
                # OK, we have a directive already, and this is not a matcher or a block,
                # which means that it is an argument
                tmp = argument_regex.match(line)
                if tmp is not None:
                    tmpline += [
                        ThemeStr(tmp[1], ThemeAttr("types", "caddyfile_argument")),
                    ]
                    line = tmp[2]
                    continue

        dumps.append(tmpline)

    return dumps
