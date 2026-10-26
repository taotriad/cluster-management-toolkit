# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A lexer for known_hosts.
"""

from typing import Any, ClassVar

from pygments.lexer import bygroups
from pygments.lexer import RegexLexer
from pygments.token import Token

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_KNOWN_HOSTS
from clustermanagementtoolkit.formatters.format_pygments_generic import format_pygments_generic


class KnownHostsLexer(RegexLexer):
    """
    A Pygments lexer for SSH known_hosts files.
    """
    name: ClassVar[str] = "KnownHosts"
    aliases: ClassVar[list[str]] = ["known_hosts"]
    filenames: ClassVar[list[str]] = ["known_hosts", "ssh_known_hosts"]

    tokens: ClassVar[dict[str, list]] = {
        "root": [
            # Comment
            (r"^#.*", Token.Comment.Single),
            # Key from keyring
            # hostname(s) keyring reference
            (r"^(\S+)(\s+)(zos-key-ring-label=)(\".*\")$",
             bygroups(Token.Name.Attribute, Token.Text.Whitespace, Token.Keyword,
                      Token.Literal.String)),  # type: ignore[no-untyped-call]
            # Revoked regular key
            # hostname(s) keytype key
            (r"^(@revoked)(\s+)(\S+)(\s+)(\S+)(\s+)(.*)$",
             bygroups(Token.Error, Token.Text.Whitespace,
                      Token.Name.Attribute, Token.Text.Whitespace, Token.Keyword,
                      Token.Text.Whitespace,
                      Token.Literal.String)),  # type: ignore[no-untyped-call]
            # Cert Authority regular key
            # hostname(s) keytype key
            (r"^(@cert-authority)(\s+)(\S+)(\s+)(\S+)(\s+)(.*)$",
             bygroups(Token.Heading, Token.Text.Whitespace,
                      Token.Name.Attribute, Token.Text.Whitespace, Token.Keyword,
                      Token.Text.Whitespace,
                      Token.Literal.String)),  # type: ignore[no-untyped-call]
            # Regular key
            # hostname(s) keytype key
            (r"^(\S+)(\s+)(\S+)(\s+)(.*)$",
             bygroups(Token.Name.Attribute, Token.Text.Whitespace, Token.Keyword,
                      Token.Text.Whitespace,
                      Token.Literal.String)),  # type: ignore[no-untyped-call]
        ]
    }


def format_known_hosts(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    known_hosts formatter; returns the text with syntax highlighting for .ssh/known_hosts.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [passthrough to format_pygments_generic]
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=KnownHostsLexer(),
                                   colorscheme=COLORSCHEME_KNOWN_HOSTS)
