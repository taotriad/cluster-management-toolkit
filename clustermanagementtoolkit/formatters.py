#! /usr/bin/env python3
# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format text as themearrays
"""

# pylint: disable=too-many-lines

import base64
import binascii
# ujson is much faster than json,
# but it might not be available
try:
    import ujson as json
    json_is_ujson = True  # pylint: disable=invalid-name
    # The exception raised by ujson when parsing fails is different
    # from what json raises
    DecodeException = ValueError
except ModuleNotFoundError:
    import json  # type: ignore
    json_is_ujson = False  # pylint: disable=invalid-name
    DecodeException = json.decoder.JSONDecodeError  # type: ignore
import io
from pathlib import Path
import re
import sys
from typing import Any, cast, TypedDict
from collections.abc import Callable, Generator
try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import yaml; "
             "you may need to (re-)run `cmt-install` or `pip3 install PyYAML`; aborting.")

import pygments
from pygments.formatter import Formatter
from pygments.lexer import RegexLexer, bygroups
import pygments.lexers
from pygments.token import Token

from clustermanagementtoolkit.cmttypes import deep_get, DictPath, FilePath, LogLevel
from clustermanagementtoolkit.cmttypes import FilePathAuditError, StatusGroup

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import split_msg, strip_ansicodes

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmtpaths import HOMEDIR, SYSTEM_PARSERS_DIR, PARSER_DIR

from clustermanagementtoolkit.curses_helper import ThemeAttr, ThemeRef, ThemeStr, themearray_len


class ColorSchemeEntry(TypedDict, total=True):
    """
    A TypedDict for colour scheme for the ThemeArrayFormatter for Pygments.

        Parameters:
            formatting (ThemeAttr): The formatting to use for the entry
            type (str): The generic type for the entry
    """
    formatting: ThemeAttr
    type: str


COLORSCHEME_CRT: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # ----BEGIN
    Token.Generic.Heading: {
        "formatting": ThemeAttr("types", "separator"),
        "type": "header",
    },
    # string
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "generic",
    },
}


COLORSCHEME_INI: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # #
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "ini_comment"),
        "type": "comment",
    },
    # [keyword]
    Token.Keyword: {
        "formatting": ThemeAttr("types", "ini_section"),
        "type": "section",
    },
    # key
    Token.Name.Attribute: {
        "formatting": ThemeAttr("types", "ini_key"),
        "type": "key",
    },
    # =
    Token.Operator: {
        "formatting": ThemeAttr("types", "ini_separator"),
        "type": "operator",
    },
    # value
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "ini_value"),
        "type": "value",
    },
}


COLORSCHEME_JSON: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # Mistakenly identified as a comment by the lexer
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # constant
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # error
    Token.Error: {
        "formatting": ThemeAttr("types", "yaml_key_error"),
        "type": "value",
    },
    # {
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "yaml_punctuation"),
        "type": "punctuation",
    },
    # key
    Token.Name.Tag: {
        "formatting": ThemeAttr("types", "yaml_key"),
        "type": "key",
    },
    # Float
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # integer
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # Quoted string
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
}


COLORSCHEME_KNOWN_HOSTS: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # #
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "known_hosts_comment"),
        "type": "comment",
    },
    # @cert-authority
    Token.Heading: {
        "formatting": ThemeAttr("types", "known_hosts_cert_authority"),
        "type": "section",
    },
    # @revoked
    Token.Error: {
        "formatting": ThemeAttr("types", "known_hosts_revoked"),
        "type": "error",
    },
    # [keyword]
    Token.Keyword: {
        "formatting": ThemeAttr("types", "known_hosts_crypto"),
        "type": "section",
    },
    # key
    Token.Name.Attribute: {
        "formatting": ThemeAttr("types", "known_hosts_hostname"),
        "type": "key",
    },
    # value
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "known_hosts_key"),
        "type": "value",
    },
}


COLORSCHEME_MOSQUITTO: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # #
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "mosquitto_comment"),
        "type": "comment",
    },
    # description|author|start on|exec|...
    Token.Keyword: {
        "formatting": ThemeAttr("types", "mosquitto_keyword"),
        "type": "comment",
    },
    # ymwdhm
    Token.Keyword.Type: {
        "formatting": ThemeAttr("types", "mosquitto_unit"),
        "type": "comment",
    },
    # 12h30m
    Token.Literal.Date: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "comment",
    },
    # value
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "mosquitto_value"),
        "type": "comment",
    },
    # integer|bool
    Token.Literal.Number: {
        "formatting": ThemeAttr("types", "mosquitto_number"),
        "type": "comment",
    },
}


COLORSCHEME_NGINX: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # key
    Token.Keyword: {
        "formatting": ThemeAttr("types", "nginx_key"),
        "type": "key",
    },
    # string
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "nginx_value"),
        "type": "value",
    },
    # integer
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "nginx_value"),
        "type": "value",
    },
    # regex
    Token.Literal.String.Regex: {
        "formatting": ThemeAttr("types", "nginx_regex"),
        "type": "regex",
    },
    # $variable
    Token.Name.Variable: {
        "formatting": ThemeAttr("types", "nginx_variable"),
        "type": "variable",
    },
    # constant
    Token.Name.Constant: {
        "formatting": ThemeAttr("types", "nginx_value"),
        "type": "value",
    },
    # ;
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "nginx_punctuation"),
        "type": "punctuation",
    },
    # key in namespace
    Token.Keyword.Namespace: {
        "formatting": ThemeAttr("types", "nginx_namespace"),
        "type": "namespace",
    },
    # #
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "nginx_comment"),
        "type": "comment",
    },
}


COLORSCHEME_POWERSHELL: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # $variable
    Token.Name.Variable: {
        "formatting": ThemeAttr("types", "powershell_variable"),
        "type": "variable",
    },
    # =
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "powershell_punctuation"),
        "type": "punctuation",
    },
    # text (possibly just whitespace?)
    Token.Text: {
        "formatting": ThemeAttr("types", "powershell_text"),
        "type": "string",
    },
    # string
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "powershell_value"),
        "type": "string",
    },
    # "
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "powershell_value"),
        "type": "string",
    },
    # function
    Token.Keyword: {
        "formatting": ThemeAttr("types", "powershell_keyword"),
        "type": "keyword",
    },
    # function name
    Token.Name: {
        "formatting": ThemeAttr("types", "powershell_name"),
        "type": "function",
    },
    # builtin
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "powershell_builtin"),
        "type": "builtin",
    },
    # # comment
    Token.Comment: {
        "formatting": ThemeAttr("types", "powershell_comment"),
        "type": "comment",
    },
    # -and
    Token.Operator: {
        "formatting": ThemeAttr("types", "powershell_operator"),
        "type": "operator",
    },
}


COLORSCHEME_PYTHON_TRACEBACK: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # Exception
    Token.Generic.Error: {
        "formatting": ThemeAttr("logview", "severity_error"),
        "type": "error",
    },
    # Traceback (most recent call last):
    Token.Generic.Traceback: {
        "formatting": ThemeAttr("logview", "severity_error"),
        "type": "error",
    },
    # False
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "value",
    },
    # raise
    Token.Keyword: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "generic",
    },
    # lineno
    Token.Literal.Number: {
        "formatting": ThemeAttr("types", "lineno"),
        "type": "lineno",
    },
    # integer
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "value",
    },
    # '
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "value",
    },
    # "
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "value",
    },
    # text
    Token.Name: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "value",
    },
    # filename
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "path"),
        "type": "path",
    },
    # self
    Token.Name.Builtin.Pseudo: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "builtin",
    },
    # Exception
    Token.Name.Exception: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "builtin",
    },
    # +
    Token.Operator: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "operator",
    },
    # ()
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "punctuation",
    },
    # File
    Token.Text: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "generic",
    },
}


COLORSCHEME_SHELLSCRIPT: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # #! /bin/sh
    Token.Comment.Hashbang: {
        "formatting": ThemeAttr("types", "shellscript_hashbang"),
        "type": "hashbang",
    },
    # # comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "shellscript_comment"),
        "type": "comment",
    },
    # variable
    Token.Name.Variable: {
        "formatting": ThemeAttr("types", "shellscript_variable"),
        "type": "variable",
    },
    # for, if, else, $(), etc.
    Token.Keyword: {
        "formatting": ThemeAttr("types", "shellscript_keyword"),
        "type": "keyword",
    },
    # number
    Token.Literal.Number: {
        "formatting": ThemeAttr("types", "shellscript_number"),
        "type": "value",
    },
    # <<EOF...EOF
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "shellscript_string"),
        "type": "value",
    },
    # string
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "shellscript_string"),
        "type": "value",
    },
    # "
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "shellscript_string"),
        "type": "value",
    },
    # Escaped values
    Token.Literal.String.Escape: {
        "formatting": ThemeAttr("types", "shellscript_escape"),
        "type": "escaped_value",
    },
    # ${}
    Token.Literal.String.Interpol: {
        "formatting": ThemeAttr("types", "shellscript_keyword"),
        "type": "keyword",
    },
    # echo
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "shellscript_builtin"),
        "type": "builtin",
    },
    # =
    Token.Operator: {
        "formatting": ThemeAttr("types", "shellscript_operator"),
        "type": "operator",
    },
    # |
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "shellscript_punctuation"),
        "type": "punctuation",
    },
    # text
    Token.Text: {
        "formatting": ThemeAttr("types", "shellscript_text"),
        "type": "text",
    },
}


COLORSCHEME_TOML: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # # comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "toml_comment"),
        "type": "comment",
    },
    # [section]
    Token.Keyword: {
        "formatting": ThemeAttr("types", "toml_section"),
        "type": "section",
    },
    # [
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "value",
    },
    # "
    Token.Literal.Date: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "date",
    },
    # bin
    Token.Literal.Number.Bin: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "value",
    },
    # float
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "value",
    },
    # hex
    Token.Literal.Number.Hex: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "value",
    },
    # integer
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "value",
    },
    # oct
    Token.Literal.Number.Oct: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "value",
    },
    # "
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "value",
    },
    # \\x09
    Token.Literal.String.Escape: {
        "formatting": ThemeAttr("types", "toml_escape"),
        "type": "escaped_value",
    },
    # string
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "toml_value"),
        "type": "value",
    },
    # =
    Token.Operator: {
        "formatting": ThemeAttr("types", "toml_key_separator"),
        "type": "operator",
    },
    # key
    Token.Name: {
        "formatting": ThemeAttr("types", "toml_key"),
        "type": "key",
    },
    # [
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "toml_punctuation"),
        "type": "punctuation",
    },
}


COLORSCHEME_XML: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # <?xml version="1.0"?>
    Token.Comment.Preproc: {
        "formatting": ThemeAttr("types", "xml_comment_preprocessor"),
        "type": "preprocessor",
    },
    # xmlns:xsi=
    Token.Name.Attribute: {
        "formatting": ThemeAttr("types", "xml_attribute_key"),
        "type": "key",
    },
    # <tag
    Token.Name.Tag: {
        "formatting": ThemeAttr("types", "xml_tag"),
        "type": "tag",
    },
    # '"http://www.w3.org/2001/XMLSchema-instance"'
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "xml_attribute_value"),
        "type": "value",
    },
    # text
    Token.Text: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "generic",
    },
}


COLORSCHEME_YAML: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # -
    Token.Punctuation.Indicator: {
        "formatting": ThemeAttr("types", "yaml_list"),
        "type": "punctuation",
    },
    # !!
    Token.Keyword.Type: {
        "formatting": ThemeAttr("types", "yaml_type"),
        "type": "keyword",
    },
    # # Comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "yaml_comment"),
        "type": "comment",
    },
    # key (sadly also seems to match %YAML and <<)
    Token.Name.Tag: {
        "formatting": ThemeAttr("types", "yaml_key"),
        "type": "key",
    },
    # :
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "yaml_key_separator"),
        "type": "punctuation",
    },
    # Constant
    Token.Name.Constant: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # Quoted string
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # integer or float
    Token.Literal.Number: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # Non-quoted string
    Token.Literal.Scalar.Plain: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # Escaped values
    Token.Literal.String.Escape: {
        "formatting": ThemeAttr("types", "yaml_escape"),
        "type": "escaped_value",
    },
    # &
    Token.Name.Label: {
        "formatting": ThemeAttr("types", "yaml_anchor"),
        "type": "anchor",
    },
    # *
    Token.Name.Variable: {
        "formatting": ThemeAttr("types", "yaml_reference"),
        "type": "reference",
    },
    # ---
    Token.Name.Namespace: {
        "formatting": ThemeAttr("types", "yaml_comment"),
        "type": "comment",
    },
}


if json_is_ujson:
    def json_dumps(obj: dict[str, Any] | list[dict[str, Any]], **kwargs: Any) -> str:
        """
        Dump Python object to JSON in text format; ujson version.

            Parameters:
                obj (dict|[dict]): The JSON object to dump
                **kwargs (dict[str, Any]): Keyword arguments
                    indent (int): Indentation (default: 2)
                    escape_forward_slashes (bool): Escape forward slashes (default: False)
            Returns:
                (str): The serialized JSON object
        """
        indent = deep_get(kwargs, DictPath("indent"), 2)
        escape_forward_slashes = deep_get(kwargs, DictPath("escape_forward_slashes"), False)
        return json.dumps(obj, indent=indent, escape_forward_slashes=escape_forward_slashes)
else:
    def json_dumps(obj: dict[str, Any] | list[dict[str, Any]], **kwargs: Any) -> str:
        """
        Dump Python object to JSON in text format; json version.

            Parameters:
                obj (dict|[dict]): The JSON object to dump
                **kwargs (dict[str, Any]): Keyword arguments
                    indent (int): Indentation (default: 2)
            Returns:
                (str): The serialized JSON object
        """
        indent = deep_get(kwargs, DictPath("indent"), 2)
        return json.dumps(obj, indent=indent)


def __str_representer(dumper: yaml.Dumper, data: Any) -> yaml.Node:
    """
    Reformat yaml with |-style str.

        Parameters:
            dumper: Opaque type internal to python-yaml
            data: Opaque type internal to python-yaml
        Returns:
            (yaml.Node): Opaque type internal to python-yaml
    """
    if "\n" in data:  # pragma: no cover
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)  # pragma: no cover


GITHUB_TAGS: tuple[tuple[str, str], ...] = (
    (":book:", "📖"),
    (":bug:", "🐛"),
    (":chart_with_upwards_trend:", "📈"),
    (":seedling:", "🌱"),
    (":sparkles:", "✨"),
)


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def format_markdown(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Markdown formatter; returns the text with syntax highlighting for a subset of Markdown.

        Parameters:
            lines (str|[str]): A list of strings *or*
                               A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
                start ((str)): Start indicator(s)
                include_start (bool): Include the start line
                end ((str)): End indicator(s)
        Returns:
            ([themearray]): A list of themearrays
    """
    format_lookup: dict[tuple[bool, bool, bool], ThemeAttr] = {
        # codeblock, bold, italics
        (False, False, False): ThemeAttr("types", "generic"),
        (True, False, False): ThemeAttr("types", "markdown_code"),
        (True, True, False): ThemeAttr("types", "markdown_code_bold"),
        (True, False, True): ThemeAttr("types", "markdown_code_italics"),
        (True, True, True): ThemeAttr("types", "markdown_code_bold_italics"),
        (False, True, False): ThemeAttr("types", "markdown_bold"),
        (False, False, True): ThemeAttr("types", "markdown_italics"),
        (False, True, True): ThemeAttr("types", "markdown_bold_italics"),
    }

    dumps: list[list[ThemeRef | ThemeStr]] = []
    start = deep_get(kwargs, DictPath("start"), None)
    include_start = deep_get(kwargs, DictPath("include_start"), False)
    strip_empty_start = deep_get(kwargs, DictPath("strip_empty_start"), False)
    strip_empty_end = deep_get(kwargs, DictPath("strip_empty_end"), False)
    end = deep_get(kwargs, DictPath("end"), None)
    use_github_tags: bool = deep_get(kwargs, DictPath("use_github_tags"), False)

    if isinstance(lines, str):
        # Remove all commented-out blocks
        lines = re.sub(r"<!--.*?-->", r"", lines, flags=re.DOTALL)
        lines = split_msg(lines)

    emptylines: list[list[ThemeRef | ThemeStr]] = []
    started = False
    if start is None:
        started = True
    codeblock = ""

    # pylint: disable-next=too-many-nested-blocks
    for line in lines:
        if started and end is not None and line.startswith(end):
            break

        if codeblock != "~~~":
            codeblock = ""

        # Skip past all non-start line until we reach the start
        if not started and start is not None:
            if not line.startswith(start):
                continue
            started = True
            # This is the start line, but we don't want to include it
            if not include_start:
                continue

        # If we've got empty lines in the buffer and we encounter a non-empty line
        # we need to flush the empty line buffer.
        if line and emptylines:
            # If there are already lines in the output it's easy; we need to keep the lines.
            # else we only keep them if strip_empty_start isn't true.
            if dumps or not strip_empty_start:
                dumps += emptylines
            emptylines = []
        elif not line:
            emptylines.append([ThemeStr("", ThemeAttr("types", "generic"))])
            continue

        if line in ("~~~", "```"):
            if codeblock == "":
                codeblock = "~~~"
            else:
                codeblock = ""
            continue
        # Replace github tags
        if use_github_tags:
            for tag, subst in GITHUB_TAGS:
                line = line.replace(tag, subst)
        # For headers we are--for now--lazy
        # Level 1 header
        if line.startswith("# "):
            tformat = ThemeAttr("types", "markdown_header_1")
            line = line.removeprefix("# ")
        # Level 2 header
        elif line.startswith("## "):
            tformat = ThemeAttr("types", "markdown_header_2")
            line = line.removeprefix("## ")
        # Level 3 header
        elif line.startswith("### "):
            tformat = ThemeAttr("types", "markdown_header_3")
            line = line.removeprefix("### ")
        else:
            tmpline: list[ThemeRef | ThemeStr] = []
            if line.startswith("    ") and not codeblock:
                tformat = ThemeAttr("types", "markdown_code")
                codeblock = "    "

            if line.lstrip().startswith(("- ", "* ", "+ ")):
                striplen = len(line) - len(line.lstrip())
                if striplen:
                    tmpline.append(ThemeStr("".ljust(striplen), ThemeAttr("types", "generic")))
                tmpline.append(ThemeRef("separators", "genericbullet"))
                line = line[themearray_len(tmpline):]

            tformat = ThemeAttr("types", "generic")

            # Rescue backticks
            line = line.replace("\\`", "<<<backtick>>>")
            code_blocks = line.split("`")

            for i, codesection in enumerate(code_blocks):
                codesection = codesection.replace("<<<backtick>>>", "\\`")
                # Toggle codeblock
                if i and codeblock in ("`", ""):
                    if codeblock == "`":
                        codeblock = ""
                    else:
                        codeblock = "`"
                # Assume consistent use of **/*/__/_
                if "**" in codesection and codeblock == "":
                    bold_sections = codesection.split("**")
                elif "__" in codesection and codeblock == "":
                    bold_sections = codesection.split("__")
                else:
                    bold_sections = [codesection]
                bold = True

                for _j, section in enumerate(bold_sections):
                    if section.startswith("#### "):
                        section = section.removeprefix("#### ")
                        bold = True
                    else:
                        bold = not bold
                    if (section.startswith("*") or " *" in section) and codeblock == "":
                        italics_sections = section.split("*")
                    elif (section.startswith("_") or " _" in section) and codeblock == "":
                        italics_sections = section.split("_")
                    else:
                        italics_sections = [section]
                    italics = True
                    for _k, italics_section in enumerate(italics_sections):
                        italics = not italics
                        if not italics_section:
                            continue
                        tmpline.append(ThemeStr(italics_section,
                                       format_lookup[(codeblock != "", bold, italics)]))
            dumps.append(tmpline)
            continue
        dumps.append([ThemeStr(line, tformat)])
        continue

    if not strip_empty_end and emptylines:
        dumps += emptylines
    return dumps


# pylint: disable-next=unused-argument
def format_binary(lines: bytes, **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Binary "formatter"; Just returns a message saying that binary views cannot be viewed.

        Parameters:
            lines (bytes): [unused]
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([themearray]): A list of themearrays
    """
    return [[ThemeStr("Binary file; cannot view", ThemeAttr("types", "generic"))]]


# pylint: disable=unused-argument
def format_none(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Noop formatter; returns the text without syntax highlighting.

        Parameters:
            lines ([str]): A list of strings
            *or*
            lines (str): a string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([themearray]): A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if isinstance(lines, str):
        lines = split_msg(lines)

    for line in lines:
        dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])
    return dumps


def format_ansible_line(line: str, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Formats a single line of an Ansible play.

        Parameters:
            line (str): a string
            **kwargs (dict[str, Any]): Keyword arguments
                override_formatting (dict): Overrides instead of default formatting
        Returns:
            (themearray): A themearray
    """
    override_formatting: dict[str, ThemeAttr] = \
        deep_get(kwargs, DictPath("override_formatting"), {})
    tmpline: list[ThemeRef | ThemeStr] = []
    formatting: ThemeAttr = ThemeAttr("types", "generic")
    if (tmp := deep_get(override_formatting, DictPath("__all"))) is not None:
        formatting = tmp

    tmpline += [
        ThemeStr(line, formatting),
    ]
    return tmpline


def format_diff_line(line: str, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Formats a single line of a diff.

        Parameters:
            line (str): a string
            **kwargs (dict[str, Any]): Keyword arguments
                override_formatting (dict): Overrides instead of default formatting
        Returns:
            (themearray): A themearray
    """
    override_formatting: dict[str, ThemeAttr] = \
        deep_get(kwargs, DictPath("override_formatting"), {})
    indent: str = deep_get(kwargs, DictPath("indent"), "")
    diffspace: str = deep_get(kwargs, DictPath("diffspace"), " ")

    tmpline: list[ThemeRef | ThemeStr] = []

    # Override all formatting?
    if (tmp := deep_get(override_formatting, DictPath("__all"))) is not None:
        diffheader_format = tmp
        diffatat_format = tmp
        diffplus_format = tmp
        diffminus_format = tmp
        diffsame_format = tmp
    else:
        diffheader_format = ThemeAttr("logview", "severity_diffheader")
        diffatat_format = ThemeAttr("logview", "severity_diffatat")
        diffplus_format = ThemeAttr("logview", "severity_diffplus")
        diffminus_format = ThemeAttr("logview", "severity_diffminus")
        diffsame_format = ThemeAttr("logview", "severity_diffsame")

    if line.startswith(("+++ ", "--- ")):
        tmpline += [
            ThemeStr(line, diffheader_format),
        ]
        return tmpline
    if line.startswith("@@ "):
        tmpline += [
            ThemeStr(line, diffatat_format),
        ]
        return tmpline
    if line.startswith(f"{indent}+{diffspace}"):
        tmpline += [
            ThemeStr(line, diffplus_format),
        ]
        return tmpline
    if line.startswith(f"{indent}-{diffspace}"):
        tmpline += [
            ThemeStr(line, diffminus_format),
        ]
        return tmpline
    tmpline += [
        ThemeStr(line, diffsame_format),
    ]
    return tmpline


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def format_yaml_line(line: str, **kwargs: Any) -> tuple[list[ThemeRef | ThemeStr],
                                                        list[list[ThemeRef | ThemeStr]]]:
    """
    Formats a single line of YAML.

        Parameters:
            line (str): a string
            **kwargs (dict[str, Any]): Keyword arguments
                override_formatting (dict): Overrides instead of default formatting
        Returns:
            (themearray): A themearray
            ([themearray]): A list of themearrays,
                            in case the YAML-line is expanded into multiple lines;
                            used when encountering keys belonging to expand_newline_fields
    """
    override_formatting: dict[str, ThemeAttr] = \
        deep_get(kwargs, DictPath("override_formatting"), {})
    expand_newline_fields: tuple[str] = deep_get(kwargs, DictPath("expand_newline_fields"), ())
    value_strip_ansicodes: bool = deep_get(kwargs, DictPath("value_strip_ansicodes"), True)
    value_expand_tabs: bool = deep_get(kwargs, DictPath("value_expand_tabs"), False)
    remnants: list[list[ThemeRef | ThemeStr]] = []

    if not isinstance(override_formatting, dict):
        raise TypeError("override_formatting should be of type(dict)")

    # Since we do not necessarily override all
    # formatting we need to set defaults;
    # doing it here instead of in the code makes
    # it easier to change the defaults of necessary
    generic_format = ThemeAttr("types", "generic")
    comment_format = ThemeAttr("types", "yaml_comment")
    key_format = ThemeAttr("types", "yaml_key")
    value_format = ThemeAttr("types", "yaml_value")
    list_format: ThemeRef | ThemeStr = ThemeRef("separators", "yaml_list")
    separator_format = ThemeAttr("types", "yaml_key_separator")
    reference_format = ThemeAttr("types", "yaml_reference")
    anchor_format = ThemeAttr("types", "yaml_anchor")

    if (tmp := deep_get(override_formatting, DictPath("__all"))) is not None:
        # We just return the line unformatted
        return [ThemeStr(line, tmp)], []

    tmpline: list[ThemeRef | ThemeStr] = []

    # [whitespace]-<whitespace><value>
    yaml_list_regex: re.Pattern[str] = re.compile(r"^(\s*)- (.*)")
    # <key>:<whitespace><value>
    # <key>:<whitespace>&<anchor>[<whitespace><value>]
    # <key>: *<alias>
    yaml_key_reference_value_regex: re.Pattern[str] = \
        re.compile(r"^([^:]+)(:\s*)(&|\*|)([^\s]+)([\s]+.+|)")

    if line.lstrip(" ").startswith("#"):
        tmpline += [
            ThemeStr(line, comment_format),
        ]
        return tmpline, remnants
    if line.lstrip(" ").startswith("- "):
        tmp = yaml_list_regex.match(line)
        if tmp is not None:
            tmpline += [
                ThemeStr(tmp[1], generic_format),
                list_format,
            ]
            line = tmp[2]
            if not line:
                return tmpline, remnants

    # pylint: disable-next=too-many-nested-blocks
    if line.endswith(":"):
        _key_format = deep_get(override_formatting, DictPath(f"{line[:-1]}#key"), key_format)
        tmpline += [
            ThemeStr(f"{line[:-1]}", _key_format),
            ThemeStr(":", separator_format),
        ]
    else:
        tmp = yaml_key_reference_value_regex.match(line)

        if (tmp is not None
                and (tmp[1].strip().startswith("\"") and tmp[1].strip().endswith("\"")
                     or (not tmp[1].strip().startswith("\"")
                         and not tmp[1].strip().endswith("\"")))):
            key = tmp[1]
            separator = tmp[2]
            reference = tmp[3]
            anchor = ""
            value_or_anchor = tmp[4]
            value = tmp[5]

            if reference:
                if value:
                    anchor = value_or_anchor
                else:
                    anchor = value_or_anchor
                    value = ""
                value_or_anchor = ""
            else:
                value = f"{value_or_anchor}{value}"
                value_or_anchor = ""

            _key_format = deep_get(override_formatting, DictPath(f"{key.strip()}#key"), key_format)
            if value.strip() in ("{", "["):
                _value_format = value_format
            else:
                _value_format = deep_get(override_formatting,
                                         DictPath(f"{key.strip()}#value"), value_format)

            if value_strip_ansicodes:
                value = strip_ansicodes(value)

            key_stripped = key.strip(" \"")
            if key_stripped in expand_newline_fields:
                split_value = split_msg(value.replace("\\n", "\n"))
                value_line_indent = 0

                for i, value_line in enumerate(split_value):
                    if value_expand_tabs:
                        tmp_split_value_line = value_line.replace("\\t", "\t").split("\t")
                        tmp_value_line = ""
                        for j, split_value_line_segment in enumerate(tmp_split_value_line):
                            tabsize = 0
                            if j < len(tmp_split_value_line):
                                tabsize = 8 - len(tmp_value_line) % 8
                            tmp_value_line += split_value_line_segment + "".ljust(tabsize)
                        value_line = tmp_value_line

                    if i == 0:
                        tmpline = [
                            ThemeStr(f"{key}", _key_format),
                            ThemeStr(f"{separator}", separator_format),
                        ]
                        if reference:
                            tmpline.append(ThemeStr(f"{reference}", reference_format))
                        if anchor:
                            tmpline.append(ThemeStr(f"{anchor}", anchor_format))
                        tmpline.append(ThemeStr(f"{value_line}", _value_format))
                        value_line_indent = len(value_line) - len(value_line.lstrip(" \""))
                    else:
                        remnants.append([
                            ThemeStr("".ljust(value_line_indent
                                        + len(key + separator + reference)), _key_format),
                            ThemeStr(f"{value_line}", _value_format),
                        ])
            else:
                if value_expand_tabs:
                    tmp_split_value = value.replace("\\t", "\t").split("\t")
                    tmp_value = ""
                    first = True
                    for j, split_value_segment in enumerate(tmp_split_value):
                        tabsize = 0
                        if j < len(tmp_split_value):
                            tabsize = 8 - len(tmp_value) % 8
                        if not first:
                            tmp_value += "".ljust(tabsize)
                        else:
                            first = False
                        tmp_value += split_value_segment
                    value = tmp_value

                tmpline += [
                    ThemeStr(f"{key}", _key_format),
                    ThemeStr(f"{separator}", separator_format),
                ]
                if reference:
                    tmpline.append(ThemeStr(f"{reference}", reference_format))
                if anchor:
                    tmpline.append(ThemeStr(f"{anchor}", anchor_format))
                if value:
                    tmpline.append(ThemeStr(f"{value}", _value_format))
        else:
            _value_format = deep_get(override_formatting, DictPath(f"{line}#value"), value_format)
            tmpline += [
                ThemeStr(f"{line}", _value_format),
            ]

    return tmpline, remnants


class KnownHostsLexer(RegexLexer):
    """
    A Pygments lexer for SSH known_hosts files.
    """
    name = "KnownHosts"
    aliases = ["known_hosts"]
    filenames = ["known_hosts", "ssh_known_hosts"]

    tokens = {
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
                      Token.Text.Whitespace, Token.Literal.String)),  # type: ignore[no-untyped-call]
            # Cert Authority regular key
            # hostname(s) keytype key
            (r"^(@cert-authority)(\s+)(\S+)(\s+)(\S+)(\s+)(.*)$",
             bygroups(Token.Heading, Token.Text.Whitespace,
                      Token.Name.Attribute, Token.Text.Whitespace, Token.Keyword,
                      Token.Text.Whitespace, Token.Literal.String)),  # type: ignore[no-untyped-call]
            # Regular key
            # hostname(s) keytype key
            (r"^(\S+)(\s+)(\S+)(\s+)(.*)$",
             bygroups(Token.Name.Attribute, Token.Text.Whitespace, Token.Keyword,
                      Token.Text.Whitespace, Token.Literal.String)),  # type: ignore[no-untyped-call]
        ]
    }


class MosquittoLexer(RegexLexer):
    """
    A Pygments lexer for Mosquitto files.
    """
    name = "Mosquitto"
    aliases = ["mosquitto"]
    filenames = ["mosquitto.conf"]

    tokens = {
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


class ThemeArrayFormatter(Formatter):
    """
    A formatter for Pygments that implements support for outputting ThemeArrays.
    """
    buffer: list[list[ThemeRef | ThemeStr]] = []
    colorscheme: dict[str, ColorSchemeEntry] = {}
    override_formatting: dict[str, ThemeAttr] = {}
    latest_key: str = ""
    lexer: Any | None = None
    unknown_ttypes: set[Any] = set()

    def __init__(self, **options: Any):
        Formatter.__init__(self, **options)
        self.colorscheme = deep_get(options, DictPath("colorscheme"), {})
        self.override_formatting = deep_get(options, DictPath("override_formatting"), {})
        self.lexer = deep_get(options, DictPath("lexer"))

    def format(self, tokensource: Generator, outfile: io.StringIO) -> None:
        # Flush the buffer
        self.buffer = []
        self.latest_key = ""

        line: list[ThemeRef | ThemeStr] = []

        for ttype, value in tokensource:
            # Use this when adding new formatters
            if ttype not in self.colorscheme \
                    and ttype not in self.unknown_ttypes:  # pragma: nocover
                sys.exit(f"{ttype=}\n{value=}")
                errmsg = [
                    [("Encountered unknown token type ", "default"),
                     (f"{ttype}", "argument"),
                     (" for substring “", "default"),
                     (f"{value}", "argument"),
                     ("“ when formatting using lexer ", "default"),
                     (f"{self.lexer}", "argument")]
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
            if value_type == "key":
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


# pylint: disable-next=too-many-branches
def format_yaml(lines: str | list[str] | dict | list[dict], **kwargs: Any) -> \
        list[list[ThemeRef | ThemeStr]]:
    """
    YAML formatter; returns the text with syntax highlighting for YAML.

        Parameters:
            lines (str|[str]|dict): A list of strings *or*
                               a string with newlines that should be split,
                               *or* a dict to dump as yaml
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([themearray]): A list of themearrays
    """
    is_json: bool = deep_get(kwargs, DictPath("json"), False)
    unfold_msg: bool = deep_get(kwargs, DictPath("unfold_msg"), False)
    yaml.add_representer(str, __str_representer)

    if isinstance(lines, str):
        # If it's one single line and starts and ends with either [] or {} we try to expand it.
        if is_json or (len(lines.splitlines()) == 1 and lines.startswith(("{", "["))
                       and lines.rstrip().endswith(("}", "]")) and unfold_msg):
            try:
                # Treat json as YAML; in case we misidentify YAML as JSON we might
                # fail to decode the data. YAML is more forgiving. Note that this
                # may result in the file being reformatted. This isn't ideal,
                # but it's the only reliable way to be able to expand a JSON/YAML structure.
                d = yaml.safe_load(lines)
                lines = json_dumps(d)
            except DecodeException:
                pass
    elif isinstance(lines, dict):
        if is_json:
            lines = json_dumps(lines)
        else:
            lines = yaml.dump(lines, sort_keys=False)
    elif isinstance(lines, list) and lines and isinstance(lines[0], dict):
        # When we get multiple objects it's because they're intended to be flattened
        # into the same logpad.
        lline = []
        for d in lines:
            if is_json:
                lline.append(json_dumps(cast(dict, d)))
            else:
                lline.append(yaml.dump(d, sort_keys=False))
        lines = "\n".join(lline)
    else:
        lines = "\n".join(cast(list[str], lines))

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    override_formatting: dict[str, ThemeAttr] = \
        deep_get(kwargs, DictPath("override_formatting"), {})

    if is_json:
        # pylint: disable-next=no-member
        lexer = pygments.lexers.JsonLexer()
        formatter = ThemeArrayFormatter(colorscheme=COLORSCHEME_JSON,
                                        override_formatting=override_formatting,
                                        lexer=lexer)
    else:
        # pylint: disable-next=no-member
        lexer = pygments.lexers.YamlLexer()
        formatter = ThemeArrayFormatter(colorscheme=COLORSCHEME_YAML,
                                        override_formatting=override_formatting,
                                        lexer=lexer)
    pygments.highlight(lines, lexer, formatter)

    return formatter.buffer


def reformat_json(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Given a string representation of JSON, reformat it.

        Parameters:
            lines (str|[str]): A list of strings *or*
                               a string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([themearray]): A list of themearrays
    """
    kwargs["json"] = True
    return format_yaml(lines, **kwargs)


# pylint: disable=unused-argument
def format_cel(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    CEL formatter; returns the text with syntax highlighting for Common Expression Language.
    Currently this formatter is equivalent to formatter_none.

        Parameters:
            lines ([str]): A list of strings
            *or*
            lines (str): a string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([themearray]): A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if isinstance(lines, str):
        lines = split_msg(lines.strip())

    for line in lines:
        dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])
    return dumps


# pylint: disable-next=too-many-branches
def format_pygments_generic(lines: str | list[str] | dict | list[dict], **kwargs: Any) -> \
        list[list[ThemeRef | ThemeStr]]:
    """
    YAML formatter; returns the text with syntax highlighting for YAML.

        Parameters:
            lines (str|[str]|dict): A list of strings *or*
                               a string with newlines that should be split,
                               *or* a dict to dump as yaml
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([themearray]): A list of themearrays
    """
    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, list):
        lines = "\n".join(lines)

    # pylint: disable-next=no-member
    lexer = deep_get(kwargs, DictPath("lexer"))
    colorscheme = deep_get(kwargs, DictPath("colorscheme"))
    formatter = ThemeArrayFormatter(colorscheme=colorscheme, lexer=lexer)
    pygments.highlight(lines, lexer, formatter)

    return formatter.buffer


def format_crt(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    CRT formatter; returns the text with syntax highlighting for certificates.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=pygments.lexers.AscLexer(),
                                   colorscheme=COLORSCHEME_CRT)


def format_haproxy(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    HAProxy formatter; returns the text with syntax highlighting for HAProxy.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if isinstance(lines, str):
        lines = split_msg(lines)

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    haproxy_section_regex: re.Pattern[str] = re.compile(r"^(\s*)(global|defaults|frontend|"
                                                        "backend|listen|resolvers|"
                                                        r"mailers|peers)(\s*)(.*)")
    haproxy_setting_regex: re.Pattern[str] = re.compile(r"^(\s*)(\S+)(\s+)(.+)")

    for line in lines:
        # Is it whitespace?
        if not line.strip():
            dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])
            continue

        # Is it a new section?
        tmp = haproxy_section_regex.match(line)
        if tmp is not None:
            whitespace1 = tmp[1]
            section = tmp[2]
            whitespace2 = tmp[3]
            label = tmp[4]
            tmpline: list[ThemeRef | ThemeStr] = [
                ThemeStr(whitespace1, ThemeAttr("types", "generic")),
                ThemeStr(section, ThemeAttr("types", "haproxy_section")),
                ThemeStr(whitespace2, ThemeAttr("types", "generic")),
                ThemeStr(label, ThemeAttr("types", "haproxy_label")),
            ]
            dumps.append(tmpline)
            continue

        # Is it settings?
        tmp = haproxy_setting_regex.match(line)
        if tmp is not None:
            whitespace1 = tmp[1]
            setting = tmp[2]
            whitespace2 = tmp[3]
            values = tmp[4]
            tmpline = [
                ThemeStr(whitespace1, ThemeAttr("types", "generic")),
                ThemeStr(setting, ThemeAttr("types", "haproxy_setting")),
                ThemeStr(whitespace2, ThemeAttr("types", "generic")),
                ThemeStr(values, ThemeAttr("types", "generic")),
            ]
            dumps.append(tmpline)
            continue

        # Unknown data; just append it unformatted
        dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])

    return dumps


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def format_caddyfile(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    CaddyFile formatter; returns the text with syntax highlighting for CaddyFiles.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

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
            if tmp is not None:
                if not block_depth and not site and (single_site or "{" in tmp[3]):
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


def format_fluentbit(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    FluentBit formatter; returns the text with syntax highlighting for FluentBit.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    key_value_regex: re.Pattern[str] = re.compile(r"^(\s*)(\S*)(\s*)(.*)")

    for line in lines:
        tmpline: list[ThemeRef | ThemeStr] = []

        if line.lstrip().startswith("#"):
            tmpline = [
                ThemeStr(line, ThemeAttr("types", "ini_comment")),
            ]
        elif line.lstrip().startswith("[") and line.rstrip().endswith("]"):
            tmpline = [
                ThemeStr(line, ThemeAttr("types", "ini_section")),
            ]
        elif not line.strip():
            tmpline = [
                ThemeStr("", ThemeAttr("types", "generic")),
            ]
        else:
            tmp = key_value_regex.match(line)
            if tmp is not None:
                indentation = tmp[1]
                key = tmp[2]
                separator = tmp[3]
                value = tmp[4]

                tmpline = [
                    ThemeStr(f"{indentation}", ThemeAttr("types", "generic")),
                    ThemeStr(f"{key}", ThemeAttr("types", "ini_key")),
                    ThemeStr(f"{separator}", ThemeAttr("types", "ini_key_separator")),
                    ThemeStr(f"{value}", ThemeAttr("types", "ini_value")),
                ]
        if tmpline:
            dumps.append(tmpline)
    return dumps


def format_ini(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    INI formatter; returns the text with syntax highlighting for INI.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=pygments.lexers.IniLexer(),
                                   colorscheme=COLORSCHEME_INI)


def format_known_hosts(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    known_hosts formatter; returns the text with syntax highlighting for .ssh/known_hosts.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=KnownHostsLexer(),
                                   colorscheme=COLORSCHEME_KNOWN_HOSTS)


def format_mosquitto(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Mosquitto formatter; returns the text with syntax highlighting for Mosquitto.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=MosquittoLexer(),
                                   colorscheme=COLORSCHEME_MOSQUITTO)


def format_nginx(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    NGINX formatter; returns the text with syntax highlighting for NGINX.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=pygments.lexers.NginxLexer(),
                                   colorscheme=COLORSCHEME_NGINX)


def format_xml(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    XML formatter; returns the text with syntax highlighting for XML.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=pygments.lexers.XmlLexer(),
                                   colorscheme=COLORSCHEME_XML)


def format_powershell(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Powershell formatter; returns the text with syntax highlighting for Powershell.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=pygments.lexers.PowerShellLexer(),
                                   colorscheme=COLORSCHEME_POWERSHELL)


def format_python_traceback(lines: str | list[str],
                            **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Python Traceback formatter; returns the text with syntax highlighting for Python Tracebacks.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=pygments.lexers.PythonTracebackLexer(),
                                   colorscheme=COLORSCHEME_PYTHON_TRACEBACK)


def format_toml(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    TOML formatter; returns the text with syntax highlighting for TOML.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=pygments.lexers.TOMLLexer(),
                                   colorscheme=COLORSCHEME_TOML)


def format_shellscript(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Shell script formatter; returns the text with syntax highlighting for shell scripts.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=pygments.lexers.BashLexer(),
                                   colorscheme=COLORSCHEME_SHELLSCRIPT)


# (startswith, endswith, formatter)
formatter_mapping: tuple[tuple[tuple[str, ...], tuple[str, ...], Callable], ...] = (
    (("Shell Script",), ("Shell Script",), format_shellscript),
    (("BASH",), ("BASH",), format_shellscript),
    (("YAML",), ("YAML",), format_yaml),
    (("JSON",), ("JSON",), format_yaml),
    (("NDJSON",), ("NDJSON",), format_yaml),
    (("",), (".yml", ".yaml", ".json", ".ndjson"), format_yaml),
    (("TOML",), ("TOML",), format_toml),
    (("",), (".toml",), format_toml),
    (("CRT",), ("CRT",), format_crt),
    (("",), (".crt", "tls.key", ".pem", "CAKey"), format_crt),
    (("XML",), ("XML",), format_xml),
    (("SVG",), ("SVG",), format_xml),
    (("",), (".xml",), format_xml),
    (("INI",), ("INI",), format_ini),
    (("",), (".ini",), format_ini),
    (("JWS",), ("JWS",), format_none),
    (("known_hosts",), ("known_hosts",), format_known_hosts),
    (("FluentBit",), ("FluentBit",), format_fluentbit),
    (("HAProxy",), ("HAProxy",), format_haproxy),
    (("haproxy.cfg",), ("haproxy.cfg",), format_haproxy),
    (("CaddyFile",), ("CaddyFile",), format_caddyfile),
    (("Mosquitto",), ("",), format_mosquitto),
    (("NGINX",), ("NGINX",), format_nginx),
    (("PowerShell",), ("PowerShell",), format_powershell),
    (("Python Traceback",), ("",), format_python_traceback),
)


def map_dataformat(dataformat: str) -> Callable[[str | list[str]], list[list[ThemeRef | ThemeStr]]]:
    """
    Identify what formatter to use, based either on a file ending or an explicit dataformat tag.

        Parameters:
            dataformat: The data format *or* the name of the file
        Returns:
            (function reference): The formatter to use
    """
    for prefix, suffix, formatter_ in formatter_mapping:
        if dataformat.startswith(prefix) and dataformat.endswith(suffix):
            return formatter_
    return format_none


# Formatters acceptable for direct use in view files
formatter_allowlist: dict[str, Callable] = {
    "format_caddyfile": format_caddyfile,
    "format_cel": format_cel,
    "format_crt": format_crt,
    "format_fluentbit": format_fluentbit,
    "format_haproxy": format_haproxy,
    "format_ini": format_ini,
    "format_known_hosts": format_known_hosts,
    "format_markdown": format_markdown,
    "format_mosquitto": format_mosquitto,
    "format_nginx": format_nginx,
    "format_none": format_none,
    "format_powershell": format_powershell,
    "format_python_traceback": format_python_traceback,
    "format_toml": format_toml,
    "format_xml": format_xml,
    "format_yaml": format_yaml,
    "reformat_json": reformat_json,
}


"""
Signatures used to detect format for ConfigMaps.
These signatures are based on the names of the ConfigMap and its data.

Fields, in order:
    Data Format
    ConfigMap Namespace
    ConfigMap Name (prefix)
    ConfigMap Name (suffix)
    ConfigMap Data Name (prefix)
    ConfigMap Data Name (suffix)

To do an exact match you can set prefix == suffix.
Note: This *may* fail if the same substring occurs twice; first and last in the name.
"""
cmdata_format: list[tuple[str, str, str, str, str, str]] = []


# These are based on the data itself
"""
Signatures used to detect format for ConfigMaps.
These signatures are based on the data itself.

Fields, in order:
    Data Format
    Data (prefix)
"""
cmdata_header: list[tuple[str, str]] = []


"""
Signatures used to detect format for ConfigMaps.
These signatures are based on the data itself, in binary format.

Fields, in order:
    Data Format
    Offset
    Data (array)
"""
cmdata_bin_header: list[tuple[str, int, tuple[int, ...]]] = []


"""
Overrides for base64 detection; some short ASCII strings
are indistinguishable from base64; override some of the false positives
we've found.
"""
cmdata_base64_overrides: list[str] = []


# pylint: disable-next=too-many-locals,too-many-branches
def import_configmap_signatures() -> StatusGroup:
    """
    Import configmap signatures and populate cmdata_format,
    cmdata_header, and cmdata_bin_header.

        Returns:
                (status): StatusGroup.OK on success, StatusGroup.WARNING
                          if file or path doesn't exist
        Raises:
            ruyaml.composer.ComposerError (synchronous mode)
            ruyaml.parser.ParserError (synchronous mode)
            ruyaml.scanner.ScannerError (synchronous mode)
            ruyaml.constructor.DuplicateKeyError (synchronous mode)
            yaml.parser.ParserError (asynchronous mode)
            cmttypes.FilePathAuditError
    """
    global cmdata_format  # pylint: disable=global-statement
    global cmdata_header  # pylint: disable=global-statement
    global cmdata_bin_header  # pylint: disable=global-statement
    global cmdata_base64_overrides  # pylint: disable=global-statement

    new_cmdata_format: list[tuple[str, str, str, str, str, str]] = []
    new_cmdata_header: list[tuple[str, str]] = []
    new_cmdata_bin_header: list[tuple[str, int, tuple[int, ...]]] = []
    status: StatusGroup = StatusGroup.OK

    d: dict[str, Any] = {}

    parser_dirs = []
    parser_dirs += deep_get(cmtlib.cmtconfig, DictPath("Pod#local_parsers"), [])
    parser_dirs.append(PARSER_DIR)
    parser_dirs.append(SYSTEM_PARSERS_DIR)

    for parser_dir in parser_dirs:
        if parser_dir.startswith("{HOME}"):
            parser_dir = parser_dir.replace("{HOME}", HOMEDIR, 1)

        path = Path(parser_dir).joinpath("configmaps.yaml")
        if not path.is_file():
            continue

        if not cmdata_format:
            try:
                d = cast(dict, secure_read_yaml(FilePath(path),
                                                directory_is_symlink=True, asynchronous=True))
            except FilePathAuditError as e:
                if "SecurityStatus.PARENT_DOES_NOT_EXIST" in str(e) \
                        or "SecurityStatus.DOES_NOT_EXIST" in str(e):
                    status = StatusGroup.WARNING
                else:
                    raise

        cmdata_base64_overrides = deep_get(d, DictPath("base64_overrides"), [])

        # The key is just the group for the type and can be safely ignored
        for _key, entry in deep_get(d, DictPath("configmap_signatures"), {}).items():
            format_name = deep_get(entry, DictPath("format_name"), "<unknown>")
            for signature in deep_get(entry, DictPath("signatures"), []):
                # Namespace of the ConfigMap
                namespace: str = deep_get(signature, DictPath("namespace"), "")
                # Name of the ConfigMap; prefix and suffix
                name_prefix: str = deep_get(signature, DictPath("prefix"), "")
                name_suffix: str = deep_get(signature, DictPath("suffix"), "")
                # Name of the data; prefix and suffix
                data_prefix: str = deep_get(signature, DictPath("data_prefix"), "")
                data_suffix: str = deep_get(signature, DictPath("data_suffix"), "")
                # Content of the data; string and binary
                data_header: str = deep_get(signature, DictPath("data_header"), "")
                data_offset: int = deep_get(signature, DictPath("data_header"), 0x0)
                data_binary: list[int] = deep_get(signature, DictPath("data_binary"), [])

                if any((namespace, name_prefix, name_suffix, data_prefix, data_suffix)):
                    new_cmdata_format.append((format_name, namespace, name_prefix, name_suffix,
                                              data_prefix, data_suffix))
                if data_header:
                    new_cmdata_header.append((format_name, data_header))
                if data_binary:
                    new_cmdata_bin_header.append((format_name, data_offset, tuple(data_binary)))

                # This is a catch-all.
                if not any((namespace, name_prefix, name_suffix,
                            data_prefix, data_suffix, data_header, data_binary)):
                    new_cmdata_format.append((format_name, namespace, name_prefix, name_suffix,
                                              data_prefix, data_suffix))

    if new_cmdata_format:
        cmdata_format = new_cmdata_format
        cmdata_header = new_cmdata_header
        cmdata_bin_header = new_cmdata_bin_header

    return status


# pylint: disable-next=too-many-locals,too-many-branches
def identify_cmdata(cmdata_name: str, cm_name: str,
                    cm_namespace: str, data: Any) -> tuple[str, Callable]:
    """
    Try to identify the format of a configmap given the name of the data,
    the name of the configmap, the namespace of the configmap, and the data itself.

        Parameters:
            cmdata_name (str): The name of the configmap data
            cm_name (str): The name of the configmap
            cm_namespace (str): The namespace of the configmap
            data (Any): The data
        Returns:
            (str, Callable):
                description (str): The description of the format
                formatter (Callable): The formatter to use
    """
    uudata: bool = False

    if not data:
        return "Empty", format_none

    if not cmdata_format:
        # This will populate cmdata_format, cmdata_header, and cmdata_bin_header
        _status = import_configmap_signatures()

    # For very short strings b64decode cannot tell the difference between
    # bas64 data and ASCII. Add workarounds for some very common short strings.
    if data in cmdata_base64_overrides:
        return "Text", format_none

    if "\n" not in data:
        try:
            decoded = base64.b64decode(data)
            if base64.b64encode(decoded) == bytes(data, encoding="utf-8"):
                uudata = True
        except binascii.Error:
            pass

    if uudata:
        try:
            data = decoded.decode("utf-8")
        except UnicodeDecodeError:
            for dataformat, offset, match_bin_infix in cmdata_bin_header:
                if len(decoded) < len(match_bin_infix) + offset:
                    continue

                if bytes(match_bin_infix) == decoded[offset:len(match_bin_infix) + offset]:
                    return dataformat, format_binary
            return "Text or Base64 encoded binary", format_none

    splitmsg = split_msg(data)
    dataformat = ""

    # We are in luck; there is an interpreter signature
    # or other type of signature to help
    if splitmsg and splitmsg[0].startswith(("#!", "-----")):
        for tmp in cmdata_header:
            tmp_dataformat, match_infix = tmp
            if match_infix in data:
                dataformat = tmp_dataformat
                break

    if not dataformat:
        for tmp_dataformat, match_cm_namespace, match_cm_name_prefix, match_cm_name_suffix, \
                match_cmdata_prefix, match_cmdata_suffix in cmdata_format:
            # pylint: disable-next=too-many-boolean-expressions
            if ((not match_cm_namespace or match_cm_namespace == cm_namespace)
                    and cm_name.startswith(match_cm_name_prefix)
                    and cm_name.endswith(match_cm_name_suffix)
                    and cmdata_name.startswith(match_cmdata_prefix)
                    and cmdata_name.endswith(match_cmdata_suffix)):
                dataformat = tmp_dataformat
                break

    formatter = map_dataformat(dataformat)

    return dataformat, formatter


def identify_formatter(dataformat: str,
                       kind: tuple[str, str] | None = None,
                       obj: dict[str, Any] | None = None,
                       path: str | None = None) -> Callable:
    """
    Identify what formatter to use for an object.

        Parameters:
            dataformat (str): [unused]
            kind ((str, str)): The kind of data
            obj (dict): The object to fetch the data from
            path (str): The path to the data to identify the formatter for
        Returns:
            (callable): A formatter
    """
    formatter = format_none

    if dataformat is None:
        if kind is not None and obj is not None and path is not None:
            if kind == ("ConfigMap", ""):
                cmdata_name = path
                cm_name = deep_get(obj, DictPath("metadata#name"))
                cm_namespace = deep_get(obj, DictPath("metadata#namespace"))
                data = deep_get(obj, DictPath(f"data#{path}"))
                dataformat, formatter = identify_cmdata(cmdata_name, cm_name, cm_namespace, data)
            else:
                raise ValueError(f"We do not know how to auto-identify data for kind {kind}")
        else:
            raise ValueError("identify_formatter() was called without dataformat, "
                             "and kind, obj, or path=None")

    return formatter
