# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import functools
import re
from typing import Any, cast

import pygments
from pygments.lexer import Lexer
from pygments.lexers.markup import MarkdownLexer
from pygments.token import Token

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_flatten
from clustermanagementtoolkit.curses_helper import themearray_len
from clustermanagementtoolkit.curses_helper import themearray_lstrip
from clustermanagementtoolkit.curses_helper import themearray_replace
from clustermanagementtoolkit.curses_helper import themearray_strip
from clustermanagementtoolkit.curses_helper import themearray_to_string

from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_MARKDOWN
from clustermanagementtoolkit.formatters.format_none import format_none
from clustermanagementtoolkit.formatters.format_markdown_table import format_markdown_table
from clustermanagementtoolkit.formatters.themearray_formatter import ThemeArrayFormatter

from clustermanagementtoolkit.github_tags import GITHUB_ALERTS, GITHUB_EMOJIS


# pylint: disable-next=too-many-branches,too-many-statements
def markdown_renderer(ttype: Any, value: str, **kwargs: Any) \
        -> tuple[Any, str | list[ThemeRef | ThemeStr], bool]:
    """
    Transform Markdown in a way that renders the document rather than just highlighting
    the syntax; this requires the ThemeArrayFormatter for Pygments; it does not work
    with standard Pygments formatters.

        Parameters:
            ttype (pygments.token.Token): The token type
            value (str): The string to render
            **kwargs (dict[str, Any]): Keyword arguments
                use_github_alerts (bool): Should GitHub alerts be used?
        Returns:
            (Token, str | [ThemeRef | ThemeStr], bool): The reformatted data
                (Token): The token type
                (str | [ThemeRef | ThemeStr]): The string to render
                (bool): Should the line be flushed on return
    """
    new_value: str | list[ThemeRef | ThemeStr] = value
    use_github_alerts: bool = deep_get(kwargs, DictPath("use_github_alerts"), False)

    if use_github_alerts and value in GITHUB_ALERTS:
        return ttype, deep_get(GITHUB_ALERTS, DictPath(value)), True

    match (ttype, value):
        case (Token.Keyword, x):
            if x in ("*", "-", "+"):
                new_value = [ThemeRef("separators", "markdownbullet")]
            elif x == "* ":
                new_value = [ThemeRef("separators", "markdownbullet"),
                             ThemeStr(" ", ThemeAttr("types", "generic"))]
            elif x in ("\t\n> ", ">\n", "> "):
                # Markdown alert
                x = x.replace("\t", "")
                if x.startswith(">"):
                    new_value = f"┃{x[1:]}"
                elif x.startswith("\n>"):
                    new_value = f"\n┃{x[2:]}"
            elif x == "\n> ":
                # Markdown alert or Quote
                new_value = f"\n┃{x[2:]}"
            elif x == "[ ]":
                new_value = x.replace("[ ]", "⬜")
            elif x == "[x]":
                new_value = x.replace("[x]", "✅")
            else:
                try:
                    index, _separator = x.split(".", maxsplit=1)
                    if int(index):
                        ttype = Token.Name.Other
                except ValueError:
                    pass
        case (Token.Generic.Heading, x):
            if x.startswith("# "):
                new_value = value[2:]
            elif re.match(r"#\d+:", x):
                # This isn't a heading; this is a reference to an issue.
                issue, description = x.split(":", maxsplit=1)
                new_value = [ThemeStr(f"{issue}:", ThemeAttr("types", "markdown_italics")),
                             ThemeStr(f"{description}", ThemeAttr("types", "generic"))]
        case (Token.Generic.Subheading, x):
            if x.startswith("## "):
                new_value = value[3:]
            elif x.startswith("### "):
                new_value = [ThemeStr(value[4:], ThemeAttr("types", "markdown_header_3"))]
            elif x.startswith("#### "):
                new_value = [ThemeStr(value[5:], ThemeAttr("types", "markdown_bold"))]
        case (Token.Literal.String.Backtick, x):
            if x.startswith("\n```") and x.endswith("```\n"):
                new_value = value[4:-4]
            elif x.startswith("`") and x.endswith("`"):
                # In backticked text we need to substitute | for something else,
                # since it can occur in tables (where | is used as separator).
                # We then need to restore the separator later (to allow for copy'n'paste).
                # To ensure that the width-counting remains correct we need to substitute
                # for a single character.
                new_value = value[1:-1].replace("|", "🜂")
        case (Token.Generic.EmphStrong, x):
            if x.startswith("___") and x.endswith("___") \
                    or x.startswith("***") and x.endswith("***"):
                new_value = value[3:-3]
        case (Token.Generic.Strong, x):
            if x.startswith("__") and x.endswith("__") \
                    or x.startswith("**") and x.endswith("**"):
                new_value = value[2:-2]
        case (Token.Generic.Emph, x):
            if x.startswith("_") and x.endswith("_") \
                    or x.startswith("*") and x.endswith("*"):
                new_value = value[1:-1]
            elif x.startswith("> "):
                tmp = x.split(" ", maxsplit=1)
                return ttype, [ThemeStr("┃ ", ThemeAttr("main", "highlight")),
                               ThemeStr(tmp[1], ThemeAttr("types", "markdown_italics"))], True
        case (Token.Text, "\\t"):
            new_value = ""

    return ttype, new_value, False


@functools.lru_cache(maxsize=32)
# pylint: disable-next=too-many-statements,too-many-branches,too-many-locals
def render_markdown(lines: str, **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Markdown renderer; renders a Markdown document to ThemeArrays.
    Note; unlike format_markdown() this renders the target document;
    it is not syntax highlighting for the source code.

        Parameters:
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
                use_github_tags (bool): Should GitHub tags be used (includes GitHub alerts)?
                raw (bool): Show raw document instead of rendering the document
        Returns:
            ([themearray]): A list of themearrays
    """
    use_github_tags: bool = deep_get(kwargs, DictPath("use_github_tags"), True)

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    # Remove all commented-out blocks
    lines = re.sub(r"<!--.*?-->\n", r"", lines, flags=re.DOTALL)

    # Replace github tags
    if use_github_tags:
        for tag, subst in GITHUB_EMOJIS:
            lines = lines.replace(tag, subst)

    lexer: Lexer = MarkdownLexer()  # type: ignore
    formatter = ThemeArrayFormatter(colorscheme=COLORSCHEME_MARKDOWN,
                                    lexer=lexer, renderer=markdown_renderer,
                                    use_github_alerts=use_github_tags)
    pygments.highlight(lines, lexer, formatter)

    formatted_data = formatter.buffer

    list_indices: dict = {}

    # Reindex lists if necessary.
    new_data: list[list[ThemeRef | ThemeStr]] = []

    for line in formatted_data:
        # Skip indentation
        newline: list[ThemeRef | ThemeStr] = []
        indent_level = 0

        if not themearray_len(themearray_strip(themearray_flatten(line))):
            list_indices = {}
            new_data.append(line)
            continue

        try:
            for i, segment in enumerate(line):
                if not isinstance(segment, ThemeStr):
                    break
                segment_len = themearray_len([segment])
                stripped_len = themearray_len(themearray_lstrip([segment]))
                if not stripped_len:
                    indent_level = segment_len

                if not stripped_len:
                    newline.append(segment)
                    continue

                if segment.get_themeattr() == ThemeAttr("main", "numbered_index"):
                    index, rest = str(segment).split(".", maxsplit=1)
                    list_index = list_indices.get(indent_level, -1)
                    if list_index in (-1, int(index) - 1):
                        list_index = int(index)
                        list_indices[indent_level] = list_index
                        # We don't need to modify this line
                        break
                    list_index = list_index + 1
                    list_indices[indent_level] = list_index
                    segment.string = f"{list_index}." + rest[0:]
                    newline.append(segment)
                    newline += line[i + 1:]
                    line = newline
                    break
        except (AttributeError, ValueError):
            pass
        new_data.append(line)

    formatted_data = new_data
    new_data = []

    # Check for tables
    table = []
    non_table = []
    table_state = "none"

    # Support non-surrounded tables.
    for line in formatted_data:
        strline = themearray_to_string(line)
        if table_state == "none":
            if "|" in strline:
                # This is possibly the starting headers of a table;
                # strip any left- and right-side lines to simplify the parsing.
                table.append(themearray_strip(themearray_strip(themearray_flatten(line)), "|"))
                non_table.append(line)
                table_state = "header"
                continue

            new_data.append(line)
            continue

        if table_state == "header":
            # Now we want a separator
            if "|" in strline and "---" in strline:
                table.append(themearray_strip(themearray_strip(themearray_flatten(line)), "|"))
                non_table.append(line)
                table_state = "separator"
                continue

            new_data += non_table
            new_data.append(line)
            table = []
            non_table = []
            table_state = "none"
            continue

        if table_state == "separator":
            if "|" in strline:
                table.append(themearray_strip(themearray_strip(themearray_flatten(line)), "|"))
                non_table.append(line)
                table_state = "data"
                continue

            new_data += non_table
            new_data.append(line)
            table = []
            non_table = []
            table_state = "none"
            continue

        if "|" in strline:
            table.append(themearray_strip(themearray_strip(themearray_flatten(line)), "|"))
            non_table.append(line)
            continue

        # We've run out of table; try to format and flush it,
        # then add the remainder.
        try:
            tmp_table = format_markdown_table(cast(list[list[ThemeRef | ThemeStr]], table))
            new_data += cast(list[list[ThemeRef | ThemeStr]], tmp_table)
        except IndexError:
            # If we get a malformed table (varying number of columns) we add
            # the lines verbatim; don't try to reformat them.
            new_data += non_table

        new_data.append(line)
        table = []
        non_table = []
        table_state = "none"

    if table and table_state == "data":
        try:
            tmp_table = format_markdown_table(cast(list[list[ThemeRef | ThemeStr]], table))
            new_data += cast(list[list[ThemeRef | ThemeStr]], tmp_table)
        except IndexError:
            # If we get a malformed table (varying number of columns) we add
            # the lines; don't try to reformat it.
            new_data += non_table
    elif non_table:
        new_data += non_table

    new_data2 = []
    for line in new_data:
        line = cast(list[ThemeRef | ThemeStr], themearray_replace(line, "🜂", "|"))
        new_data2.append(line)

    return new_data2
