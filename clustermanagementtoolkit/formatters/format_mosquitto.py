# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A lexer for Mosquitto.
"""

from typing import Any, ClassVar

from pygments.lexer import bygroups, RegexLexer
from pygments.token import Token

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_MOSQUITTO
from clustermanagementtoolkit.formatters.format_pygments_generic import format_pygments_generic


class MosquittoLexer(RegexLexer):
    """
    A Pygments lexer for Mosquitto files.
    """
    name: ClassVar[str] = "Mosquitto"
    aliases: ClassVar[list[str]] = ["mosquitto"]
    filenames: ClassVar[list[str]] = ["mosquitto.conf"]

    tokens: ClassVar[dict[str, list]] = {
        "root": [
            # Comment
            (r"^#.*", Token.Comment.Single),
            # Single directive
            # respawn|...
            (r"^(\S+)\s*$", Token.Keyword),
            # 2-tuple with bool
            # queue_qos0_messages true
            (r"^(start on|\S+)(\s+)(true|false)\s*$",
             bygroups(Token.Keyword, Token.Text.Whitespace,
                      Token.Literal.Number)),  # type: ignore[no-untyped-call]
            # 2-tuple with number or list of numbers
            # Note: This rule isn't ideal; it'll accept
            # lists with trailing commas and even things like -, -,- and similar stupid things.
            # listener 1883
            # accept_protocol_versions 3, 4
            # accept_protocol_versions 3,4,5
            (r"^(\S+)(\s*)(-*\d+)(-*[\d, ]*)\s*$",
             bygroups(Token.Keyword, Token.Text.Whitespace,
                      Token.Literal.Number,
                      Token.Literal.Number)),  # type: ignore[no-untyped-call]
            # 2-tuple with time period; we could use Token.Literal.Date for the entire period,
            # but we want the unit separate from the Integer.
            # persistent_client_expiration 2m
            (r"^(\S+)(\s+)(\d+)([ymwdh])\s*$",
             bygroups(Token.Keyword, Token.Text.Whitespace,
                      Token.Literal.Date,
                      Token.Keyword.Type)),  # type: ignore[no-untyped-call]
            # 2-tuple with quoted string
            # start on|keyword value
            # description "Quoted string"
            (r"^(start on|\S+)(\s+)(\".*?\")\s*$",
             bygroups(Token.Keyword, Token.Text.Whitespace,
                      Token.Literal.String)),  # type: ignore[no-untyped-call]
            # 2-tuple with string
            # start on|keyword value
            # description unquotedstring
            (r"^(start on|\S+)(\s+)(\S+)\s*$",
             bygroups(Token.Keyword, Token.Text.Whitespace,
                      Token.Literal.String)),  # type: ignore[no-untyped-call]
            # 3-tuple with numerical value followed by string
            # listener 0 path
            (r"^(\S+)(\s+)(\d+)(\s)(\S*)\s*$",
             bygroups(Token.Keyword, Token.Text.Whitespace,
                      Token.Literal.Number, Token.Text.Whitespace,
                      Token.Literal.String)),  # type: ignore[no-untyped-call]
            # 3-tuple with string followed by string
            (r"^(\S+)(\s+)(\S+)(\s)(\S*)\s*$",
             bygroups(Token.Keyword, Token.Text.Whitespace,
                      Token.Keyword.Type, Token.Text.Whitespace,
                      Token.Literal.String)),  # type: ignore[no-untyped-call]
        ]
    }


def format_mosquitto(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Mosquitto formatter; returns the text with syntax highlighting for Mosquitto.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [passthrough to format_pygments_generic]
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=MosquittoLexer(),
                                   colorscheme=COLORSCHEME_MOSQUITTO)
