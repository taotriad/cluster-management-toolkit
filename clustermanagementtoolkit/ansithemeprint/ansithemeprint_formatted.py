# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format and print data using Pygments; (currently) supports YAML and JSON.
"""

import sys
from typing import Any

try:
    import pygments
    import pygments.formatters
    import pygments.lexers
    from pygments.token import Comment, Error, Generic, Keyword, Name, Number, Operator
    from pygments.token import String, Token, Whitespace
    SYNTAX_HIGHLIGHTING: bool = True
except ModuleNotFoundError:  # pragma: no cover
    SYNTAX_HIGHLIGHTING = False

from clustermanagementtoolkit.ansithemeprint.theme import get_theme, get_themepath

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

# ansithemeprint is used by cmt-install.py,
# so definitions from it cannot be be used unconditionally.
if SYNTAX_HIGHLIGHTING:
    COLORSCHEME_JSON: dict[Any, tuple[str, str]] = {
        Token: ("", ""),
        Token.Literal: ("magenta", "brightmagenta"),
        Token.Punctuation: ("gray", "gray"),

        Whitespace: ("gray", "brightblack"),
        Comment: ("gray", "brightblack"),
        Comment.Preproc: ("cyan", "brightcyan"),
        Keyword: ("cyan", "brightcyan"),
        Keyword.Type: ("cyan", "brightcyan"),
        Operator.Word: ("magenta", "brightmagenta"),
        Name.Builtin: ("cyan", "brightcyan"),
        Name.Function: ("green", "brightgreen"),
        Name.Namespace: ("_cyan_", "_brightcyan_"),
        Name.Class: ("_green_", "_brightgreen_"),
        Name.Exception: ("cyan", "brightcyan"),
        Name.Decorator: ("brightblack", "gray"),
        Name.Variable: ("red", "brightred"),
        Name.Constant: ("red", "brightred"),
        Name.Attribute: ("cyan", "brightcyan"),
        Name.Tag: ("brightyellow", "brightyellow"),
        String: ("magenta", "brightmagenta"),
        Number: ("magenta", "brightmagenta"),

        Generic.Deleted: ("brightred", "brightred"),
        Generic.Inserted: ("green", "brightgreen"),
        Generic.Heading: ("**", "**"),
        Generic.Subheading: ("*magenta*", "*brightmagenta*"),
        Generic.Prompt: ("**", "**"),
        Generic.Error: ("brightred", "brightred"),

        Error: ("_brightred_", "_brightred_"),
    }

    COLORSCHEME_YAML: dict[Any, tuple[str, str]] = {
        Token: ("", ""),
        Token.Literal: ("magenta", "brightmagenta"),
        Token.Punctuation: ("yellow", "brightyellow"),

        Whitespace: ("gray", "brightblack"),
        Comment: ("gray", "brightblack"),
        Comment.Preproc: ("cyan", "brightcyan"),
        Keyword: ("blue", "brightblue"),
        Keyword.Type: ("green", "brightgreen"),
        Operator.Word: ("magenta", "brightmagenta"),
        Name.Builtin: ("cyan", "brightcyan"),
        Name.Function: ("green", "brightgreen"),
        Name.Namespace: ("_cyan_", "_brightcyan_"),
        Name.Class: ("_green_", "_brightgreen_"),
        Name.Exception: ("cyan", "brightcyan"),
        Name.Decorator: ("brightblack", "gray"),
        Name.Variable: ("red", "brightred"),
        Name.Constant: ("red", "brightred"),
        Name.Attribute: ("cyan", "brightcyan"),
        Name.Tag: ("brightcyan", "brightcyan"),
        String: ("magenta", "brightmagenta"),
        Number: ("magenta", "brightmagenta"),

        Generic.Deleted: ("brightred", "brightred"),
        Generic.Inserted: ("green", "brightgreen"),
        Generic.Heading: ("**", "**"),
        Generic.Subheading: ("*magenta*", "*brightmagenta*"),
        Generic.Prompt: ("**", "**"),
        Generic.Error: ("brightred", "brightred"),

        Error: ("_brightred_", "_brightred_"),
    }

    COLORSCHEME: dict[Any, tuple[str, str]] = {
        Token: ("", ""),
        Token.Literal: ("magenta", "brightmagenta"),
        Token.Punctuation: ("gray", "gray"),

        Whitespace: ("gray", "brightblack"),
        Comment: ("gray", "brightblack"),
        Comment.Preproc: ("cyan", "brightcyan"),
        Keyword: ("blue", "brightblue"),
        Keyword.Type: ("cyan", "brightcyan"),
        Operator.Word: ("magenta", "brightmagenta"),
        Name.Builtin: ("cyan", "brightcyan"),
        Name.Function: ("green", "brightgreen"),
        Name.Namespace: ("_cyan_", "_brightcyan_"),
        Name.Class: ("_green_", "_brightgreen_"),
        Name.Exception: ("cyan", "brightcyan"),
        Name.Decorator: ("brightblack", "gray"),
        Name.Variable: ("red", "brightred"),
        Name.Constant: ("red", "brightred"),
        Name.Attribute: ("cyan", "brightcyan"),
        Name.Tag: ("brightblue", "brightblue"),
        String: ("yellow", "yellow"),
        Number: ("magenta", "brightmagenta"),

        Generic.Deleted: ("brightred", "brightred"),
        Generic.Inserted: ("green", "brightgreen"),
        Generic.Heading: ("**", "**"),
        Generic.Subheading: ("*magenta*", "*brightmagenta*"),
        Generic.Prompt: ("**", "**"),
        Generic.Error: ("brightred", "brightred"),

        Error: ("_brightred_", "_brightred_"),
    }


# pylint: disable-next=too-many-branches
def ansithemeprint_formatted(text: str | list[str], **kwargs: Any) -> None:
    """
    Print a themearray;
    a themearray is a list of format strings of the format:
    (string, theme_attr_ref); context is implicitly understood to be term.

        Parameters:
            text (str | [str]): The text to format and print
            **kwargs (dict[str, Any]): Keyword arguments
                input_format (str): The input format:
                    "json": JSON
                    "text": Plain text  [default]
                    "yaml": YAML
                stderr (bool): True to print to stderr, False to print to stdout
                color (str):
                    "always": Always use ANSI-formatting
                    "never": Never use ANSI-formatting
                    "auto": Use ANSI-formatting except when redirected [default]
                background (str): Dark or light background
                    "dark": Dark background [default]
                    "light": Light background
        Raises:
            ProgrammingError: Function called without initializing ansithemestr
    """
    stderr: bool = deep_get(kwargs, DictPath("stderr"), False)
    color: str = deep_get(kwargs, DictPath("color"), "auto")
    input_format: str = deep_get(kwargs, DictPath("input_format"), "text")
    background: str = deep_get(kwargs, DictPath("background"), "dark")

    use_color = None

    if not get_theme() or get_themepath() is None:
        raise ProgrammingError("ansithemeprint() used without calling init_ansithemeprint() first; "
                               "this is a programming error.")

    match color:
        case "auto":
            if stderr:
                use_color = sys.stderr.isatty()
            else:
                use_color = sys.stdout.isatty()
        case "always":
            use_color = True
        case "never":
            use_color = False
        case _:
            raise ValueError("Incorrect value for color passed to ansithemeprint_formatted(); "
                             "the only valid values are ”always”, ”auto”, and ”never”; "
                             "this is a programming error.")

    reformatted = ""

    if isinstance(text, str):
        reformatted = text
    elif isinstance(text, list):
        reformatted = "\n".join(text)

    if SYNTAX_HIGHLIGHTING:
        lexer = None

        colorscheme = COLORSCHEME
        match input_format:
            case "yaml":
                # pylint: disable-next=no-member
                lexer = pygments.lexers.YamlLexer()
                colorscheme = COLORSCHEME_YAML
            case "json":
                # pylint: disable-next=no-member
                lexer = pygments.lexers.JsonLexer()
                colorscheme = COLORSCHEME_JSON
        # pylint: disable-next=no-member
        formatter = pygments.formatters.TerminalFormatter(bg=background, colorscheme=colorscheme)

        if stderr:
            output_file = sys.stderr
        else:
            output_file = sys.stdout

        if input_format == "text" or not use_color or not SYNTAX_HIGHLIGHTING or not lexer:
            print(reformatted, file=output_file)
        else:
            print(pygments.highlight(reformatted, lexer, formatter), file=output_file)
    else:
        print(reformatted)
