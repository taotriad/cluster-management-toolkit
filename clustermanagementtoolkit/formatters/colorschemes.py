# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

# pylint: disable=too-many-lines

from typing import Any, TypedDict

from pygments.token import Token

from clustermanagementtoolkit.curses_helper import ThemeAttr


class ColorSchemeEntry(TypedDict, total=True):
    """
    A TypedDict for colour scheme for the ThemeArrayFormatter for Pygments.

        Parameters:
            formatting (ThemeAttr): The formatting to use for the entry
            type (str): The generic type for the entry
    """
    formatting: ThemeAttr
    type: str


COLORSCHEME_CADDYFILE: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # # Comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "caddyfile_comment"),
        "type": "comment",
    },
    # 5s
    Token.Keyword: {
        "formatting": ThemeAttr("types", "caddyfile_directive"),
        "type": "keyword",
    },
    # 5s
    Token.Literal.Number: {
        "formatting": ThemeAttr("types", "caddyfile_argument"),
        "type": "argument",
    },
    # "foo"
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "caddyfile_argument"),
        "type": "argument",
    },
    # @post
    Token.Name.Decorator: {
        "formatting": ThemeAttr("types", "caddyfile_matcher"),
        "type": "text",
    },
    # {$SITE_ADDRESS}
    Token.Name.Variable: {
        "formatting": ThemeAttr("types", "caddyfile_variable"),
        "type": "variable",
    },
    #  { }
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "caddyfile_punctuation"),
        "type": "punctuation",
    },
    # .:53
    Token.Text: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "text",
    },
}


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


COLORSCHEME_DMESG: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # string
    Token.Text: {
        "formatting": ThemeAttr("types", "dmesg_string"),
        "type": "string",
    },
    # 00:14.3: firmware: failed to load iwl-debug-yoyo.bin (-2)
    Token.Generic.Error: {
        "formatting": ThemeAttr("types", "dmesg_error"),
        "type": "error",
    },
    # #AC: crashing the kernel on kernel split_locks and warning on user-space split_locks
    Token.Generic.Strong: {
        "formatting": ThemeAttr("types", "dmesg_bold"),
        "type": "bold",
    },
    # Command line:
    Token.Keyword: {
        "formatting": ThemeAttr("types", "dmesg_keyword"),
        "type": "keyword",
    },
    # [    0.000000]
    Token.Literal.Number: {
        "formatting": ThemeAttr("types", "dmesg_timestamp"),
        "type": "timestamp",
    },
}


COLORSCHEME_DOCKER: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # string
    Token.Text: {
        "formatting": ThemeAttr("types", "docker_string"),
        "type": "string",
    },
    # # comment
    Token.Comment: {
        "formatting": ThemeAttr("types", "docker_comment"),
        "type": "comment",
    },
    # ARG
    Token.Keyword: {
        "formatting": ThemeAttr("types", "docker_keyword"),
        "type": "keyword",
    },
    # 0
    Token.Literal.Number: {
        "formatting": ThemeAttr("types", "docker_value"),
        "type": "value",
    },
    # ${GOLANG_BASE}
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "docker_interpol"),
        "type": "string",
    },
    # "all=-w -s"
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "docker_value"),
        "type": "value",
    },
    # Escaped values
    Token.Literal.String.Escape: {
        "formatting": ThemeAttr("types", "docker_escape"),
        "type": "escaped_value",
    },
    # ${}
    Token.Literal.String.Interpol: {
        "formatting": ThemeAttr("types", "docker_interpol"),
        "type": "keyword",
    },
    # 'Intel®'
    Token.Literal.String.Single: {
        "formatting": ThemeAttr("types", "docker_value"),
        "type": "value",
    },
    # cd
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "docker_builtin"),
        "type": "builtin",
    },
    # FINAL_BASE
    Token.Name.Variable: {
        "formatting": ThemeAttr("types", "docker_variable"),
        "type": "variable",
    },
    # =
    Token.Operator: {
        "formatting": ThemeAttr("types", "docker_operator"),
        "type": "operator",
    },
    # ;
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "docker_punctuation"),
        "type": "punctuation",
    },
}


COLORSCHEME_GO: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # /* Comment */
    Token.Comment.Multiline: {
        "formatting": ThemeAttr("types", "go_comment"),
        "type": "comment",
    },
    # // Comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "go_comment"),
        "type": "comment",
    },
    # return
    Token.Keyword: {
        "formatting": ThemeAttr("types", "go_keyword"),
        "type": "keyword",
    },
    # false
    Token.Keyword.Constant: {
        "formatting": ThemeAttr("types", "go_value"),
        "type": "value",
    },
    # type
    Token.Keyword.Declaration: {
        "formatting": ThemeAttr("types", "go_declaration"),
        "type": "keyword",
    },
    # package
    Token.Keyword.Namespace: {
        "formatting": ThemeAttr("types", "go_namespace"),
        "type": "namespace",
    },
    # float64
    Token.Keyword.Type: {
        "formatting": ThemeAttr("types", "go_type"),
        "type": "type",
    },
    # 1.2
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "go_value"),
        "type": "value",
    },
    # 0x0a
    Token.Literal.Number.Hex: {
        "formatting": ThemeAttr("types", "go_value"),
        "type": "value",
    },
    # 42
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "go_value"),
        "type": "value",
    },
    # 'a'
    Token.Literal.String.Char: {
        "formatting": ThemeAttr("types", "go_value"),
        "type": "value",
    },
    # "string"
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "go_value"),
        "type": "value",
    },
    # Name
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "go_builtin"),
        "type": "builtin",
    },
    # Name
    Token.Name.Other: {
        "formatting": ThemeAttr("types", "go_name"),
        "type": "name",
    },
    # *
    Token.Operator: {
        "formatting": ThemeAttr("types", "go_operator"),
        "type": "operator",
    },
    # (
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "go_punctuation"),
        "type": "punctuation",
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
    # <!-- Comment -->
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
        "formatting": ThemeAttr("types", "uri"),
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
    # # comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "promql_comment"),
        "type": "comment",
    },
    # count
    Token.Keyword: {
        "formatting": ThemeAttr("types", "promql_keyword"),
        "type": "keyword",
    },
    # rate
    Token.Keyword.Reserved: {
        "formatting": ThemeAttr("types", "promql_builtin"),
        "type": "keyword",
    },
    # 0.05
    Token.Literal.Number.Float: {
        "formatting": ThemeAttr("types", "promql_value"),
        "type": "value",
    },
    # 0
    Token.Literal.Number.Integer: {
        "formatting": ThemeAttr("types", "promql_value"),
        "type": "value",
    },
    # MissingTargetNamespace
    Token.Literal.String: {
        "formatting": ThemeAttr("types", "promql_string"),
        "type": "value",
    },
    # condition
    Token.Name.Label: {
        "formatting": ThemeAttr("types", "promql_label"),
        "type": "label",
    },
    # cco_credentials_requests_conditions
    Token.Name.Variable: {
        "formatting": ThemeAttr("types", "promql_variable"),
        "type": "variable",
    },
    # =
    Token.Operator: {
        "formatting": ThemeAttr("types", "promql_operator"),
        "type": "operator",
    },
    # and
    Token.Operator.Word: {
        "formatting": ThemeAttr("types", "promql_keyword"),
        "type": "operator",
    },
    # {}
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "promql_punctuation"),
        "type": "punctuation",
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


COLORSCHEME_REGO: dict[Any, ColorSchemeEntry] = {
    # <whitespace>
    Token.Text.Whitespace: {
        "formatting": ThemeAttr("types", "generic"),
        "type": "whitespace",
    },
    # # comment
    Token.Comment.Single: {
        "formatting": ThemeAttr("types", "rego_comment"),
        "type": "comment",
    },
    # package
    Token.Keyword: {
        "formatting": ThemeAttr("types", "rego_keyword"),
        "type": "keyword",
    },
    # "msg"
    Token.Literal.String.Double: {
        "formatting": ThemeAttr("types", "rego_string"),
        "type": "value",
    },
    # :=
    Token.Literal.Number: {
        "formatting": ThemeAttr("types", "rego_number"),
        "type": "value",
    },
    # k8srequiredlabels
    Token.Name: {
        "formatting": ThemeAttr("types", "rego_name"),
        "type": "variable",
    },
    # input
    Token.Name.Builtin: {
        "formatting": ThemeAttr("types", "rego_builtin"),
        "type": "builtin",
    },
    # :=
    Token.Operator: {
        "formatting": ThemeAttr("types", "rego_operator"),
        "type": "operator",
    },
    # [
    Token.Punctuation: {
        "formatting": ThemeAttr("types", "rego_punctuation"),
        "type": "punctuation",
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
