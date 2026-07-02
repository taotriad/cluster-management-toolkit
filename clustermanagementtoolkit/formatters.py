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
import copy
from datetime import datetime
import io
import json
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
from pygments.lexer import RegexLexer, Lexer, bygroups
from pygments.lexers.asc import AscLexer
from pygments.lexers.configs import IniLexer, NginxConfLexer, TOMLLexer
try:
    from pygments.lexers.cel import CELLexer
    CELLEXER_AVAILABLE = True
except ModuleNotFoundError:
    # CELLexer is available from Pygments 2.22
    CELLEXER_AVAILABLE = False
from pygments.lexers.css import CssLexer
from pygments.lexers.data import JsonLexer, YamlLexer
from pygments.lexers.diff import DiffLexer
from pygments.lexers.html import HtmlLexer, XmlLexer
from pygments.lexers.javascript import JavascriptLexer
from pygments.lexers.markup import MarkdownLexer
from pygments.lexers.promql import PromQLLexer
from pygments.lexers.python import PythonLexer, PythonTracebackLexer
from pygments.lexers.shell import BashLexer, PowerShellLexer
from pygments.token import Token

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmttypes import deep_get, deep_pop, DictPath, FilePath, LogLevel
from clustermanagementtoolkit.cmttypes import FilePathAuditError, StatusGroup

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import get_since, split_msg, strip_ansicodes

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml
from clustermanagementtoolkit.cmtio_yaml import json_dumps

from clustermanagementtoolkit.cmtpaths import HOMEDIR, SYSTEM_PARSERS_DIR, PARSER_DIR

from clustermanagementtoolkit.curses_helper import ThemeAttr, ThemeRef, ThemeStr, themearray_len
from clustermanagementtoolkit.curses_helper import themearray_to_string, themearray_strip
from clustermanagementtoolkit.curses_helper import themearray_lstrip
from clustermanagementtoolkit.curses_helper import themearray_compact, themearray_split
from clustermanagementtoolkit.curses_helper import themearray_flatten, themearray_replace

from clustermanagementtoolkit.generators import format_list, format_numerical_with_units
from clustermanagementtoolkit.generators import format_timestamp

from clustermanagementtoolkit.github_tags import GITHUB_ALERTS, GITHUB_EMOJIS


class ColorSchemeEntry(TypedDict, total=True):
    """
    A TypedDict for colour scheme for the ThemeArrayFormatter for Pygments.

        Parameters:
            formatting (ThemeAttr): The formatting to use for the entry
            type (str): The generic type for the entry
    """
    formatting: ThemeAttr
    type: str


COLORSCHEME_CEL: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # // Comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "cel_comment"),
        "type": "comment",
    },
    # in
    Token.Keyword: {
        "formatting": ThemeAttr("types", "cel_keyword"),
        "type": "keyword",
    },
    # true
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "cel_constant"),
        "type": "constant",
    },
    # namespace
    Token.Keyword.Reserved: {
        "formatting": ThemeAttr("types", "cel_keyword"),
        "type": "keyword",
    },
    # 3.14159
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "cel_value"),
        "type": "value",
    },
    # 100
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "cel_value"),
        "type": "value",
    },
    # string
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "cel_value"),
        "type": "value",
    },
    # \\n
    Token.Literal.String.Escape: {
        "formatting": ThemeAttr("types", "cel_escape"),
        "type": "escape",
    },
    # name
    Token.Name: {
        "formatting": ThemeAttr("types", "cel_name"),
        "type": "name",
    },
    # ||
    Token.Operator: {
        "formatting": ThemeAttr("types", "cel_operator"),
        "type": "operator",
    },
    # .
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "cel_punctuation"),
        "type": "punctuation",
    },
}


COLORSCHEME_CRT: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # #
    Token.Comment: {
        "formatting": ThemeAttr("types", "separator"),
        "type": "comment",
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


COLORSCHEME_CSS: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # /* */
    Token.Comment: {
        "formatting": ThemeAttr("types", "css_comment"),
        "type": "comment",
    },
    # !important
    Token.Comment.Preproc: {
        "formatting": ThemeAttr("types", "css_comment_preprocessor"),
        "type": "preprocessor",
    },
    # padding
    Token.Keyword: {
        "formatting": ThemeAttr("types", "css_keyword"),
        "type": "keyword",
    },
    # none
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "css_constant"),
        "type": "constant",
    },
    # -moz-
    Token.Keyword.Pseudo: {
        "formatting": ThemeAttr("types", "css_pseudo"),
        "type": "pseudo",
    },
    # %
    Token.Keyword.Type: {
        "formatting": ThemeAttr("types", "css_type"),
        "type": "type",
    },
    # 1.25
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "css_value"),
        "type": "value",
    },
    # #1a1c1e
    Token.Literal.Number.Hex: {
        "formatting": ThemeAttr("types", "css_value"),
        "type": "value",
    },
    # 12
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "css_value"),
        "type": "value",
    },
    # "quoted string"
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "css_value"),
        "type": "value",
    },
    # images/ui-bg_highlight-soft_100_eeeeee_1x100.png
    Token.Literal.String.Other: {
        "formatting": ThemeAttr("types", "css_value"),
        "type": "value",
    },
    # Arial
    Token.Name: {
        "formatting": ThemeAttr("types", "css_value"),
        "type": "value",
    },
    # rgb
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "css_builtin"),
        "type": "builtin",
    },
    # ethical-sidebar
    Token.Name.Class: {
        "formatting": ThemeAttr("types", "css_class"),
        "type": "class",
    },
    # hover
    Token.Name.Decorator: {
        "formatting": ThemeAttr("types", "css_decorator"),
        "type": "decorator",
    },
    # var
    Token.Name.Function: {
        "formatting": ThemeAttr("types", "css_function"),
        "type": "function",
    },
    # furo-sidebar-ad-placement
    Token.Name.Namespace: {
        "formatting": ThemeAttr("types", "css_namespace"),
        "type": "namespace",
    },
    # a
    Token.Name.Tag: {
        "formatting": ThemeAttr("types", "css_tag"),
        "type": "tag",
    },
    # --sidebar-item-spacing-vertical
    Token.Name.Variable: {
        "formatting": ThemeAttr("types", "css_variable"),
        "type": "variable",
    },
    # >
    Token.Operator: {
        "formatting": ThemeAttr("types", "css_operator"),
        "type": "operator",
    },
    # #
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "css_punctuation"),
        "type": "punctuation",
    },
    # text
    Token.Text: {
        "formatting": ThemeAttr("types", "default"),
        "type": "string",
    },
}


COLORSCHEME_DIFF: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # diff --git
    Token.Generic.Heading: {
        "formatting": ThemeAttr("logview", "severity_diffheader"),
        "type": "header",
    },
    # +++
    Token.Generic.Inserted: {
        "formatting": ThemeAttr("logview", "severity_diffplus"),
        "type": "header",
    },
    # ---
    Token.Generic.Deleted: {
        "formatting": ThemeAttr("logview", "severity_diffminus"),
        "type": "header",
    },
    # @@
    Token.Generic.Subheading: {
        "formatting": ThemeAttr("logview", "severity_diffatat"),
        "type": "header",
    },
    # text
    Token.Text: {
        "formatting": ThemeAttr("logview", "severity_diffsame"),
        "type": "string",
    },
}


COLORSCHEME_HTML: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # /* [Embedded JavaScript and Embedded CSS] */
    Token.Comment: {
        "formatting": ThemeAttr("types", "css_comment"),
        "type": "comment",
    },
    # // [Embedded JavaScript]
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "javascript_comment"),
        "type": "comment",
    },
    # <!-- -->
    Token.Comment.Multiline: {
        "formatting": ThemeAttr("types", "xml_comment"),
        "type": "comment",
    },
    # <!DOCTYPE html>
    Token.Comment.Preproc: {
        "formatting": ThemeAttr("types", "html_comment_preprocessor"),
        "type": "preprocessor",
    },
    # media
    Token.Keyword: {
        "formatting": ThemeAttr("types", "html_keyword"),
        "type": "keyword",
    },
    # serif
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "html_value"),
        "type": "value",
    },
    # var [Embedded JavaScript]
    Token.Keyword.Declaration: {
        "formatting": ThemeAttr("types", "javascript_builtin"),
        "type": "keyword",
    },
    # %
    Token.Keyword.Type: {
        "formatting": ThemeAttr("types", "html_type"),
        "type": "type",
    },
    # 1.2
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "html_value"),
        "type": "value",
    },
    # 100
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "html_value"),
        "type": "value",
    },
    # #083194
    Token.Literal.Number.Hex: {
        "formatting": ThemeAttr("types", "html_value"),
        "type": "value",
    },
    # en
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "html_value"),
        "type": "value",
    },
    # "double quoted"
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "html_value"),
        "type": "value",
    },
    # /^toclevel/ [Embedded JavaScript]
    Token.Literal.String.Regex: {
        "formatting": ThemeAttr("types", "javascript_value"),
        "type": "value",
    },
    # 'single quoted'
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "html_value"),
        "type": "value",
    },
    # Georgia
    Token.Name: {
        "formatting": ThemeAttr("types", "html_value"),
        "type": "value",
    },
    # Constant
    Token.Name.Attribute: {
        "formatting": ThemeAttr("types", "html_attribute"),
        "type": "attribute",
    },
    # Array [Embedded JavaScript]
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "javascript_builtin"),
        "type": "builtin",
    },
    # full-width-table
    Token.Name.Class: {
        "formatting": ThemeAttr("types", "html_tag"),
        "type": "tag",
    },
    # visited
    Token.Name.Decorator: {
        "formatting": ThemeAttr("types", "html_decorator"),
        "type": "decorator",
    },
    # &8212;
    Token.Name.Entity: {
        "formatting": ThemeAttr("types", "html_escape"),
        "type": "escape",
    },
    # #toctitle
    Token.Name.Namespace: {
        "formatting": ThemeAttr("types", "html_namespace"),
        "type": "namespace",
    },
    # asciidoc [Embedded JavaScript]
    Token.Name.Other: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "other",
    },
    # <tag
    Token.Name.Tag: {
        "formatting": ThemeAttr("types", "html_tag"),
        "type": "tag",
    },
    # =
    Token.Operator: {
        "formatting": ThemeAttr("types", "html_operator"),
        "type": "operator",
    },
    # new [Embedded JavaScript]
    Token.Operator.Word: {
        "formatting": ThemeAttr("types", "javascript_builtin"),
        "type": "operator",
    },
    # <
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "html_punctuation"),
        "type": "punctuation",
    },
    # text
    Token.Text: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "generic",
    },
}


COLORSCHEME_MARKDOWN: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # text
    Token.Text: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "text",
    },
    # List index; non-numbered
    Token.Keyword: {
        "formatting": ThemeAttr("main", "highlight"),
        "type": "text",
    },
    # List index; numbered
    Token.Name.Other: {
        "formatting": ThemeAttr("main", "numbered_index"),
        "type": "text",
    },
    # URL
    Token.Name.Attribute: {
        "formatting": ThemeAttr("types", "url"),
        "type": "text",
    },
    # Not sure what this is
    Token.Name.Label: {
        "formatting": ThemeAttr("main", "highlight"),
        "type": "text",
    },
    # URL description
    Token.Name.Tag: {
        "formatting": ThemeAttr("main", "highlight"),
        "type": "text",
    },
    # # header
    Token.Generic.Heading: {
        "formatting": ThemeAttr("types", "markdown_header_1"),
        "type": "header",
    },
    # ## header
    Token.Generic.Subheading: {
        "formatting": ThemeAttr("types", "markdown_header_2"),
        "type": "header",
    },
    # ___text___ ***text***
    Token.Generic.EmphStrong: {
        "formatting": ThemeAttr("types", "markdown_bold_italics"),
        "type": "text",
    },
    # __text__ **text**
    Token.Generic.Strong: {
        "formatting": ThemeAttr("types", "markdown_bold"),
        "type": "text",
    },
    # _text_ *text*
    Token.Generic.Emph: {
        "formatting": ThemeAttr("types", "markdown_italics"),
        "type": "text",
    },
    # bug numbers #31563 and @mentions
    Token.Name.Entity: {
        "formatting": ThemeAttr("types", "markdown_italics"),
        "type": "code",
    },
    # `code` ```code block```
    Token.Literal.String.Backtick: {
        "formatting": ThemeAttr("types", "markdown_code"),
        "type": "code",
    },
    # # (used by subparsing of code blocks with specified language)
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "yaml_comment"),
        "type": "comment",
    },
    # Constant (used by subparsing of code blocks with specified language)
    Token.Name.Constant: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # : (used by subparsing of code blocks with specified language)
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "yaml_key_separator"),
        "type": "punctuation",
    },
    # - (used by subparsing of code blocks with specified language)
    Token.Punctuation.Indicator: {
        "formatting": ThemeAttr("types", "yaml_list"),
        "type": "punctuation",
    },
    # Non-quoted string (used by subparsing of code blocks with specified language)
    Token.Literal.Scalar.Plain: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
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


COLORSCHEME_JAVASCRIPT: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # //
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "javascript_comment"),
        "type": "comment",
    },
    # /* */
    Token.Comment.Multiline: {
        "formatting": ThemeAttr("types", "javascript_comment"),
        "type": "comment",
    },
    # while
    Token.Keyword: {
        "formatting": ThemeAttr("types", "javascript_builtin"),
        "type": "keyword",
    },
    # false
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "javascript_value"),
        "type": "value",
    },
    # var
    Token.Keyword.Declaration: {
        "formatting": ThemeAttr("types", "javascript_builtin"),
        "type": "keyword",
    },
    # 1
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "javascript_value"),
        "type": "value",
    },
    # "foo"
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "javascript_value"),
        "type": "value",
    },
    # /^toclevel/
    Token.Literal.String.Regex: {
        "formatting": ThemeAttr("types", "javascript_value"),
        "type": "value",
    },
    # 'foo'
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "javascript_value"),
        "type": "value",
    },
    # Array
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "javascript_builtin"),
        "type": "builtin",
    },
    # TypeError
    Token.Name.Exception: {
        "formatting": ThemeAttr("types", "javascript_exception"),
        "type": "exception",
    },
    # env
    Token.Name.Other: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "other",
    },
    # =
    Token.Operator: {
        "formatting": ThemeAttr("types", "javascript_operator"),
        "type": "operator",
    },
    # new
    Token.Operator.Word: {
        "formatting": ThemeAttr("types", "javascript_builtin"),
        "type": "operator",
    },
    # .
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "javascript_punctuation"),
        "type": "punctuation",
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
    # .Synopsis
    Token.Literal.String.Doc: {
        "formatting": ThemeAttr("types", "powershell_doc"),
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
    # [String]
    Token.Name.Constant: {
        "formatting": ThemeAttr("types", "powershell_constant"),
        "type": "constant",
    },
    # # comment
    Token.Comment: {
        "formatting": ThemeAttr("types", "powershell_comment"),
        "type": "comment",
    },
    # <# comment
    Token.Comment.Multiline: {
        "formatting": ThemeAttr("types", "powershell_comment"),
        "type": "comment",
    },
    # -and
    Token.Operator: {
        "formatting": ThemeAttr("types", "powershell_operator"),
        "type": "operator",
    },
}


COLORSCHEME_PROMQL: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # text
    Token.Text: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "generic",
    },
    # # comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "promql_comment"),
        "type": "comment",
    },
    # 0.05
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "promql_value"),
        "type": "value",
    },
    # 50
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "promql_value"),
        "type": "value",
    },
    # "
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "promql_string"),
        "type": "value",
    },
    # '
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "promql_string"),
        "type": "value",
    },
    # cco_credentials_requests_conditions
    Token.Name: {
        "formatting": ThemeAttr("types", "promql_name"),
        "type": "name",
    },
    # sum
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "promql_builtin"),
        "type": "builtin",
    },
    # is
    Token.Operator.Word: {
        "formatting": ThemeAttr("types", "promql_keyword"),
        "type": "keyword",
    },
    # {}
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "promql_punctuation"),
        "type": "punctuation",
    },
    # >
    Token.Operator: {
        "formatting": ThemeAttr("types", "promql_operator"),
        "type": "keyword",
    },
}


COLORSCHEME_PYTHON: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # text
    Token.Text: {
        "formatting": ThemeAttr("types", "python_text"),
        "type": "generic",
    },
    # f"{foo}" {}
    Token.Literal.String.Interpol: {
        "formatting": ThemeAttr("types", "python_interpol"),
        "type": "keyword",
    },
    # f
    Token.Literal.String.Affix: {
        "formatting": ThemeAttr("types", "python_value"),
        "type": "keyword",
    },
    # binary
    Token.Literal.Number.Bin: {
        "formatting": ThemeAttr("types", "python_value"),
        "type": "value",
    },
    # float
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "python_value"),
        "type": "value",
    },
    # hex
    Token.Literal.Number.Hex: {
        "formatting": ThemeAttr("types", "python_value"),
        "type": "value",
    },
    # integer
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "python_value"),
        "type": "value",
    },
    # octal
    Token.Literal.Number.Oct: {
        "formatting": ThemeAttr("types", "python_value"),
        "type": "value",
    },
    # \n
    Token.Literal.String.Escape: {
        "formatting": ThemeAttr("types", "python_escape"),
        "type": "escape",
    },
    # '
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "python_value"),
        "type": "string",
    },
    # "
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "python_value"),
        "type": "string",
    },
    # builtin
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "python_builtin"),
        "type": "builtin",
    },
    # @decorator
    Token.Name.Decorator: {
        "formatting": ThemeAttr("types", "python_builtin"),
        "type": "builtin",
    },
    # self
    Token.Name.Builtin.Pseudo: {
        "formatting": ThemeAttr("types", "python_builtin"),
        "type": "builtin",
    },
    # =
    Token.Operator: {
        "formatting": ThemeAttr("types", "python_operator"),
        "type": "operator",
    },
    # # comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "python_comment"),
        "type": "comment",
    },
    # #! /usr/bin/python3
    Token.Comment.Hashbang: {
        "formatting": ThemeAttr("types", "python_comment"),
        "type": "hashbang",
    },
    # """
    Token.Literal.String.Doc: {
        "formatting": ThemeAttr("types", "python_docstring"),
        "type": "comment",
    },
    # ,
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "python_punctuation"),
        "type": "punctuation",
    },
    # try
    Token.Keyword: {
        "formatting": ThemeAttr("types", "python_keyword"),
        "type": "keyword",
    },
    # datetime
    Token.Name: {
        "formatting": ThemeAttr("types", "python_name"),
        "type": "name",
    },
    # datetime
    Token.Name.Namespace: {
        "formatting": ThemeAttr("types", "python_name"),
        "type": "name",
    },
    # class
    Token.Name.Class: {
        "formatting": ThemeAttr("types", "python_keyword"),
        "type": "keyword",
    },
    # is
    Token.Operator.Word: {
        "formatting": ThemeAttr("types", "python_keyword"),
        "type": "keyword",
    },
    # Exception
    Token.Name.Exception: {
        "formatting": ThemeAttr("types", "python_exception"),
        "type": "exception",
    },
    # function
    Token.Name.Function: {
        "formatting": ThemeAttr("types", "python_function"),
        "type": "function",
    },
    # __init__
    Token.Name.Function.Magic: {
        "formatting": ThemeAttr("types", "python_function"),
        "type": "function",
    },
    # __doc__
    Token.Name.Variable.Magic: {
        "formatting": ThemeAttr("types", "python_variable"),
        "type": "function",
    },
    # from
    Token.Keyword.Namespace: {
        "formatting": ThemeAttr("types", "python_builtin"),
        "type": "builtin",
    },
    # None
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "python_builtin"),
        "type": "builtin",
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
    # <!-- -->
    Token.Comment.Multiline: {
        "formatting": ThemeAttr("types", "xml_comment"),
        "type": "comment",
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
    # :
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "yaml_key_separator"),
        "type": "punctuation",
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
    # Constant
    Token.Name.Constant: {
        "formatting": ThemeAttr("types", "yaml_value"),
        "type": "value",
    },
    # key (sadly also seems to match %YAML and <<)
    Token.Name.Tag: {
        "formatting": ThemeAttr("types", "yaml_key"),
        "type": "key",
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


def format_markdown_table(lines: list[list[ThemeRef | ThemeStr]]) -> list[list[ThemeStr]]:
    """
    Given suitable data create a table from ThemeArray-formatted Markdown.

        Parameters:
            lines ([[ThemeRef | ThemeStr]]): A list of themearrays
        Returns:
            ([[ThemeStr]])): A reformatted list of themearrays
    """
    headers: list[list[ThemeStr]] = []

    headers = themearray_split(themearray_compact(lines[0]), separator="|")
    headers = [themearray_compact(cast(list[ThemeRef | ThemeStr], header)) for header in headers]
    headers = [themearray_strip(header) for header in headers]

    column_count: int = len(headers) * 2 + 1
    widths: list[int] = \
        [themearray_len(cast(list[ThemeRef | ThemeStr], header)) for header in headers]
    i: int = 0

    rows: list[list[ThemeStr]] = []

    # Calculate the widths; skip the headers
    for line in lines[2:]:
        row = themearray_split(themearray_compact(line), separator="|")
        row = [themearray_compact(cast(list[ThemeRef | ThemeStr], segment)) for segment in row]
        row = [themearray_strip(segment) for segment in row]
        for i, field in enumerate(row):
            try:
                widths[i] = max(themearray_len(cast(list[ThemeRef | ThemeStr], row[i])), widths[i])
            except IndexError:
                pass

    # We've got the widths, time to construct the table:

    # First the top line
    columns: list[list[ThemeStr]] = [[] for n in range(column_count)]
    for i in range(len(headers)):
        columns[i * 2] = [ThemeStr("┬", ThemeAttr("types", "generic"))]
        columns[i * 2 + 1] = [ThemeStr("".ljust(widths[i], "─"), ThemeAttr("types", "generic"))]
    columns[0] = [ThemeStr("┌", ThemeAttr("types", "generic"))]
    columns.append([ThemeStr("┐", ThemeAttr("types", "generic"))])
    rows.append(themearray_compact([x for xx in columns for x in xx]))

    # Now the header
    columns = [[] for n in range(column_count)]
    for i, header in enumerate(headers):
        # reformatted header (unless explicitly formatted)
        if len(header) == 1:
            header = [ThemeStr(themearray_to_string(cast(list[ThemeRef | ThemeStr], header)),
                               ThemeAttr("types", "markdown_table_header"))]
        columns[i * 2] = [ThemeStr("│", ThemeAttr("types", "generic"))]
        columns[i * 2 + 1] = themearray_strip(header) \
                         + [ThemeStr("".ljust(widths[i]
                                              - themearray_len(cast(list[ThemeRef | ThemeStr],
                                                                    header))),
                                     ThemeAttr("types", "generic"))]
    columns.append([ThemeStr("│", ThemeAttr("types", "generic"))])
    rows.append(themearray_compact([x for xx in columns for x in xx]))

    # Separator between header and data
    columns = [[] for n in range(column_count)]
    for i in range(len(headers)):
        columns[i * 2] = [ThemeStr("┼", ThemeAttr("types", "generic"))]
        columns[i * 2 + 1] = [ThemeStr("".ljust(widths[i], "─"), ThemeAttr("types", "generic"))]
    columns[0] = [ThemeStr("├", ThemeAttr("types", "generic"))]
    columns.append([ThemeStr("┤", ThemeAttr("types", "generic"))])
    rows.append(themearray_compact([x for xx in columns for x in xx]))

    # Data
    for line in lines[2:]:
        columns = [[] for n in range(column_count)]
        row = themearray_split(themearray_compact(line), separator="|")
        row = [themearray_compact(cast(list[ThemeRef | ThemeStr], segment)) for segment in row]
        row = [themearray_strip(segment) for segment in row]
        for i, field in enumerate(row):
            columns[i * 2] = [ThemeStr("│", ThemeAttr("types", "generic"))]
            data = field
            columns[i * 2 + 1] = data \
                + [ThemeStr("".ljust(widths[i]
                                     - themearray_len(cast(list[ThemeRef | ThemeStr], data))),
                            ThemeAttr("types", "generic"))]
        columns.append([ThemeStr("│", ThemeAttr("types", "generic"))])
        rows.append(themearray_compact([x for xx in columns for x in xx]))

    # Finally the bottom line
    columns = [[] for n in range(column_count)]
    for i in range(len(headers)):
        columns[i * 2] = [ThemeStr("┴", ThemeAttr("types", "generic"))]
        columns[i * 2 + 1] = [ThemeStr("".ljust(widths[i], "─"), ThemeAttr("types", "generic"))]
    columns[0] = [ThemeStr("└", ThemeAttr("types", "generic"))]
    columns.append([ThemeStr("┘", ThemeAttr("types", "generic"))])
    rows.append(themearray_compact([x for xx in columns for x in xx]))

    return rows


# pylint: disable-next=too-many-statements,too-many-branches,too-many-locals
def render_markdown(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Markdown renderer; renders a Markdown document to ThemeArrays.
    Note; unlike format_markdown() this renders the target document;
    it is not syntax highlighting for the source code.

        Parameters:
            lines (str|[str]): A list of strings *or*
                               A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
                start ((str)): Start indicator(s)
                include_start (bool): Include the start line
                end ((str)): End indicator(s)
                use_github_tags (bool): Should GitHub tags be used (includes GitHub alerts)?
        Returns:
            ([themearray]): A list of themearrays
    """
    use_github_tags: bool = deep_get(kwargs, DictPath("use_github_tags"), True)

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, list):
        lines = "\n".join(lines)

    # Remove all commented-out blocks
    lines = re.sub(r"<!--.*?-->\n", r"", lines, flags=re.DOTALL)

    # Replace github tags
    if use_github_tags:
        for tag, subst in GITHUB_EMOJIS:
            lines = lines.replace(tag, subst)

    # TODO: we might want to add a hack to make tables look better
    # when we replace dim/bold in tables we lose the width.

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


# pylint: disable-next=too-many-branches
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
            elif x == "\n> ":
                # Markdown alert or Quote
                if x.startswith("\n>"):
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


class ThemeArrayFormatter(Formatter):
    """
    A formatter for Pygments that implements support for outputting ThemeArrays.
    """
    buffer: list[list[ThemeRef | ThemeStr]] = []
    colorscheme: dict[str, ColorSchemeEntry] = {}
    override_formatting: dict[str, ThemeAttr] = {}
    latest_key: str = ""
    lexer: Any | None = None
    renderer: Callable | None = None
    unknown_ttypes: set[Any] = set()
    use_github_alerts: bool = False

    def __init__(self, **options: Any):
        Formatter.__init__(self, **options)
        self.colorscheme = deep_get(options, DictPath("colorscheme"), {})
        self.override_formatting = deep_get(options, DictPath("override_formatting"), {})
        self.lexer = deep_get(options, DictPath("lexer"))
        self.renderer = deep_get(options, DictPath("renderer"))
        self.use_github_alerts = deep_get(options, DictPath("use_github_alerts"), False)

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
                tmpvalue = value.replace("\"", "\\\"")
                errmsg = [
                    [("Encountered unknown token type ", "default"),
                     (f"{ttype}", "argument"),
                     (" for substring “", "default"),
                     (f"{tmpvalue}", "argument"),
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

    new_lines = copy.deepcopy(lines)

    if isinstance(new_lines, list) and len(new_lines) == 1:
        new_lines = new_lines[0]

    if isinstance(new_lines, str):
        # If it's one single line and starts and ends with either [] or {} we try to expand it.
        if is_json or (len(new_lines.splitlines()) == 1 and new_lines.startswith(("{", "["))
                       and new_lines.rstrip().endswith(("}", "]")) and unfold_msg):
            try:
                # Treat json as YAML; in case we misidentify YAML as JSON we might
                # fail to decode the data. YAML is more forgiving. Note that this
                # may result in the file being reformatted. This isn't ideal,
                # but it's the only reliable way to be able to expand a JSON/YAML structure.
                d = yaml.safe_load(new_lines)
                new_lines = json_dumps(d)
            except (ValueError, json.decoder.JSONDecodeError):
                pass
    elif isinstance(new_lines, dict):
        new_lines = copy.deepcopy(new_lines)

        focus_mode: str = deep_get(kwargs, DictPath("focus_mode"), "Disabled")
        focus_filters: list[dict[str, list[str]]] = deep_get(kwargs, DictPath("focus_filters"), {})

        for focus_filter in deep_get(focus_filters, DictPath(focus_mode), []):
            if isinstance(focus_filter, list):
                path, key = focus_filter
                deep_pop(new_lines, DictPath(path), key, None)
            else:
                new_lines.pop(focus_filter, None)

        if is_json:
            new_lines = json_dumps(new_lines)
        else:
            new_lines = yaml.dump(new_lines, sort_keys=False)
    elif isinstance(new_lines, list) and new_lines and isinstance(new_lines[0], dict):
        # When we get multiple objects it's because they're intended to be flattened
        # into the same logpad.
        lline = []
        for d in new_lines:
            if is_json:
                lline.append(json_dumps(d))
            else:
                lline.append(yaml.dump(d, sort_keys=False))
        new_lines = "\n".join(lline)
    else:
        new_lines = "\n".join(cast(list[str], new_lines))

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(new_lines)

    override_formatting: dict[str, ThemeAttr] = \
        deep_get(kwargs, DictPath("override_formatting"), {})

    if is_json:
        lexer: Lexer = JsonLexer()
        formatter = ThemeArrayFormatter(colorscheme=COLORSCHEME_JSON,
                                        override_formatting=override_formatting,
                                        lexer=lexer)
    else:
        lexer = YamlLexer()
        formatter = ThemeArrayFormatter(colorscheme=COLORSCHEME_YAML,
                                        override_formatting=override_formatting,
                                        lexer=lexer)
    pygments.highlight(new_lines, lexer, formatter)

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


def format_pygments_generic(lines: str | list[str], **kwargs: Any) -> \
        list[list[ThemeRef | ThemeStr]]:
    """
    Generic formatter; returns the text with syntax highlighting.

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

    lexer = deep_get(kwargs, DictPath("lexer"))
    colorscheme = deep_get(kwargs, DictPath("colorscheme"))
    formatter = ThemeArrayFormatter(colorscheme=colorscheme, lexer=lexer)
    pygments.highlight(lines, lexer, formatter)

    return formatter.buffer


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


def format_cel(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    CEL formatter; returns the text with syntax highlighting for Common Expression Language.
    If pygments 2.19.2 or newer is available this will provide syntax highlighting;
    otherwise format_none will be used instead.

        Parameters:
            lines ([str]): A list of strings
            *or*
            lines (str): a string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([themearray]): A list of themearrays
    """
    if CELLEXER_AVAILABLE:
        return format_pygments_generic(lines, **kwargs,
                                       lexer=CELLexer(),
                                       colorscheme=COLORSCHEME_CEL)
    return format_none(lines)


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
                                   lexer=AscLexer(),
                                   colorscheme=COLORSCHEME_CRT)


def format_css(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    CSS formatter; returns the text with syntax highlighting for cascading stylesheets.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=CssLexer(),
                                   colorscheme=COLORSCHEME_CSS)


def format_diff(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Diff formatter; returns the text with syntax highlighting for unified and context diffs.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=DiffLexer(),
                                   colorscheme=COLORSCHEME_DIFF)


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
                    ThemeStr(f"{separator}", ThemeAttr("types", "ini_separator")),
                    ThemeStr(f"{value}", ThemeAttr("types", "ini_value")),
                ]
        if tmpline:
            dumps.append(tmpline)
    return dumps


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


def format_html(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    HTML formatter; returns the text with syntax highlighting for HTML.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=HtmlLexer(),
                                   colorscheme=COLORSCHEME_HTML)


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
                                   lexer=IniLexer(),
                                   colorscheme=COLORSCHEME_INI)


def format_javascript(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    JavaScript formatter; returns the text with syntax highlighting for JavaScript.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=JavascriptLexer(),
                                   colorscheme=COLORSCHEME_JAVASCRIPT)


# pylint: disable-next=too-many-locals,too-many-branches
def format_key_value(lines: dict[str, Any], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    key[:type]:value formatter; returns the text with syntax highlighting for key:value data.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
                typed (bool): Should the data be interpreted as key:type:value?
                sort (bool): Should the data be sorted?
                value_type (str): type to use if data isn't typed; default is str
        Returns:
            list[themearray]: A list of themearrays
    """
    typed = deep_get(kwargs, DictPath("typed"), False)
    sort = deep_get(kwargs, DictPath("sort"), False)
    value_type = deep_get(kwargs, DictPath("value_type"), "default")
    override_types: dict[str, str] = deep_get(kwargs, DictPath("override_types"), {})
    value_mappings: dict[str, str] = deep_get(kwargs, DictPath("value_mappings"), {})
    separator_type: str = deep_get(kwargs, DictPath("separator#type"), "keyvalue")
    selected: bool = False

    dumps: list[list[ThemeRef | ThemeStr]] = []

    if sort:
        lines = dict(natsorted(lines.items()))

    for key, d in lines.items():
        if not typed:
            d = {value_type: d}
        for vtype, value in d.items():
            vtype = deep_get(override_types, DictPath(key), vtype)
            match key, vtype, value:
                case key, _, _ if key in value_mappings:
                    context = deep_get(value_mappings, DictPath(f"{key}#{value}#context"), "types")
                    ftype = deep_get(value_mappings, DictPath(f"{key}#{value}#type"), "generic")
                    formatted_value: ThemeStr | list[ThemeRef | ThemeStr] = \
                        ThemeStr(value, ThemeAttr(context, ftype))
                case _, "age", _:
                    formatted_value = \
                        format_numerical_with_units(f"{get_since(value)}", selected, ftype="age")
                case _, "timestamp", _:
                    formatted_value = format_timestamp(value, selected)
                case _, _, value if isinstance(value, datetime):
                    formatted_value = format_timestamp(value, selected)
                case _, "bool" | "boolean", _:
                    formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))
                case _, _, _ if isinstance(value, bool):
                    formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))
                case _, "str" | "string", _:
                    formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))
                case _, "hex", _ if isinstance(value, (str, int)):
                    formatted_value = \
                        format_numerical_with_units(str(value), selected, ftype="numerical",
                                                    non_units=set("0123456789abcdefABCDEF"))
                case _, "int" | "integer" | "float", _:
                    formatted_value = \
                        format_numerical_with_units(value, selected, ftype="numerical")
                case _, _, value if isinstance(value, (float, int)):
                    formatted_value = \
                        format_numerical_with_units(str(value), selected, ftype="numerical")
                case _, "list" | "tuple", _:
                    formatted_value = format_list(list(value), fieldlen=0, pad=False)
                case _, _, value if isinstance(value, (list, tuple)):
                    formatted_value = format_list(list(value), fieldlen=0, pad=False)
                case _, _, _:
                    formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))

            if isinstance(formatted_value, list):
                dumps.append([
                    cast(ThemeRef | ThemeStr, ThemeStr(key, ThemeAttr("types", "key"))),
                    ThemeRef("separators", separator_type),
                ] + formatted_value)
            else:
                dumps.append([
                    ThemeStr(key, ThemeAttr("types", "key")),
                    ThemeRef("separators", separator_type),
                    formatted_value,
                ])

    return dumps


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
                                   lexer=NginxConfLexer(),
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
                                   lexer=XmlLexer(),
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
                                   lexer=PowerShellLexer(),
                                   colorscheme=COLORSCHEME_POWERSHELL)


def format_promql(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Prometheus Query Language formatter; returns the text with syntax highlighting for PromQL.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=PythonLexer(),
                                   colorscheme=COLORSCHEME_PROMQL)


def format_python(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Python formatter; returns the text with syntax highlighting for Python.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    return format_pygments_generic(lines, **kwargs,
                                   lexer=PythonLexer(),
                                   colorscheme=COLORSCHEME_PYTHON)


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
                                   lexer=PythonTracebackLexer(),
                                   colorscheme=COLORSCHEME_PYTHON_TRACEBACK)


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
                                   lexer=BashLexer(),
                                   colorscheme=COLORSCHEME_SHELLSCRIPT)


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
                                   lexer=TOMLLexer(),
                                   colorscheme=COLORSCHEME_TOML)


# (startswith, endswith, formatter)
formatter_mapping: tuple[tuple[tuple[str, ...], tuple[str, ...], Callable], ...] = (
    (("shell",), ("shell",), format_shellscript),
    (("shell script",), ("shell script",), format_shellscript),
    (("",), (".sh",), format_shellscript),
    (("",), (".bash",), format_shellscript),
    (("bash",), ("bash",), format_shellscript),
    (("",), (".diff",), format_diff),
    (("",), (".patch",), format_diff),
    (("diff",), ("diff",), format_diff),
    (("",), (".zsh",), format_shellscript),
    (("zsh",), ("zsh",), format_shellscript),
    (("",), (".html",), format_html),
    (("html",), ("html",), format_html),
    (("json",), ("json",), format_yaml),
    (("ndjson",), ("ndjson",), format_yaml),
    (("yaml",), ("yaml",), format_yaml),
    (("",), (".yml", ".yaml", ".json", ".ndjson"), format_yaml),
    (("toml",), ("toml",), format_toml),
    (("",), (".toml",), format_toml),
    (("cel",), ("cel",), format_cel),
    (("",), (".cel",), format_cel),
    (("crt",), ("crt",), format_crt),
    (("",), (".crt", "tls.key", ".pem", "CAKey"), format_crt),
    (("css",), ("css",), format_css),
    (("",), (".css",), format_css),
    (("",), (".xml",), format_xml),
    (("xml",), ("xml",), format_xml),
    (("",), (".svg",), format_xml),
    (("svg",), ("svg",), format_xml),
    (("",), (".xhtml",), format_html),
    (("xhtml",), ("xhtml",), format_html),
    (("",), (".xml",), format_xml),
    (("ini",), ("ini",), format_ini),
    (("",), (".ini",), format_ini),
    (("js",), ("js",), format_javascript),
    (("javascript",), ("javascript",), format_javascript),
    (("",), (".js",), format_javascript),
    (("jws",), ("jws",), format_none),
    (("known_hosts",), ("known_hosts",), format_known_hosts),
    (("fluentbit",), ("fluentbit",), format_fluentbit),
    (("haproxy",), ("haproxy",), format_haproxy),
    (("haproxy.cfg",), ("haproxy.cfg",), format_haproxy),
    (("caddyfile",), ("caddyfile",), format_caddyfile),
    (("markdown",), ("markdown",), render_markdown),
    (("md",), ("md",), render_markdown),
    (("",), (".md",), render_markdown),
    (("mosquitto",), ("",), format_mosquitto),
    (("nginx",), ("nginx",), format_nginx),
    (("ps1",), ("ps1",), format_powershell),
    (("",), (".ps1",), format_powershell),
    (("powershell",), ("powershell",), format_powershell),
    (("",), (".promql",), format_promql),
    (("promql",), ("promql",), format_promql),
    (("python",), ("",), format_python),
    (("py",), ("py",), format_python),
    (("",), (".py",), format_python),
    (("python traceback",), ("",), format_python_traceback),
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
        if dataformat.lower().startswith(prefix) \
                and dataformat.lower().endswith(suffix):
            return formatter_
    return format_none


# Formatters acceptable for direct use in view files
formatter_allowlist: dict[str, Callable] = {
    "format_autodetect": map_dataformat,
    "format_caddyfile": format_caddyfile,
    "format_cel": format_cel,
    "format_crt": format_crt,
    "format_css": format_css,
    "format_fluentbit": format_fluentbit,
    "format_haproxy": format_haproxy,
    "format_html": format_html,
    "format_ini": format_ini,
    "format_javascript": format_javascript,
    "format_key_value": format_key_value,
    "format_known_hosts": format_known_hosts,
    "format_mosquitto": format_mosquitto,
    "format_nginx": format_nginx,
    "format_none": format_none,
    "format_powershell": format_powershell,
    "format_promql": format_promql,
    "format_python": format_python,
    "format_python_traceback": format_python_traceback,
    "format_toml": format_toml,
    "format_xml": format_xml,
    "format_yaml": format_yaml,
    "reformat_json": reformat_json,
    "render_markdown": render_markdown,
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
            if base64.b64encode(decoded) == bytes(data, encoding="utf-8", errors="replace"):
                uudata = True
        except binascii.Error:
            pass

    if uudata:
        try:
            data = decoded.decode("utf-8", errors="replace")
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
            raise ValueError(f"{__name__}() called without dataformat, and kind, obj, or path=None")

    return formatter
