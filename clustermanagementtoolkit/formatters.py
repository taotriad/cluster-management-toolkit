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
from pathlib import Path
import re
import sys
from typing import Any, cast
from collections.abc import Callable
try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import yaml; "
             "you may need to (re-)run `cmt-install` or `pip3 install PyYAML`; aborting.")

from clustermanagementtoolkit.cmttypes import deep_get, DictPath, FilePath
from clustermanagementtoolkit.cmttypes import FilePathAuditError, StatusGroup

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import split_msg, strip_ansicodes

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmtpaths import HOMEDIR, SYSTEM_PARSERS_DIR, PARSER_DIR

from clustermanagementtoolkit.curses_helper import ThemeAttr, ThemeRef, ThemeStr, themearray_len


if json_is_ujson:
    def json_dumps(obj: dict) -> str:
        """
        Dump Python object to JSON in text format; ujson version.

            Parameters:
                obj (dict): The JSON object to dump
            Returns:
                (str): The serialized JSON object
        """
        indent = 2
        return json.dumps(obj, indent=indent, escape_forward_slashes=False)
else:
    def json_dumps(obj: dict) -> str:
        """
        Dump Python object to JSON in text format; json version.

            Parameters:
                obj (dict): The JSON object to dump
            Returns:
                (str): The serialized JSON object
        """
        indent = 2
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
    if "\n" in data:  # pragma: nocover
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)  # pragma: nocover


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

    emptylines: list[ThemeRef | ThemeStr] = []
    started = False
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

        if not line:
            emptylines.append(ThemeStr("", ThemeAttr("types", "generic")))
            continue
        if (not strip_empty_start or dumps) and emptylines:
            dumps.append(emptylines)
            emptylines = []

        if line in ("~~~", "```"):
            if codeblock == "":
                codeblock = "~~~"
            else:
                codeblock = ""
            continue
        # Replace github tags
        if use_github_tags:
            line = line.replace(":bug:", "🐛")
            line = line.replace(":seedling:", "🌱")
            line = line.replace(":chart_with_upwards_trend:", "📈")
            line = line.replace(":book:", "📖")
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
        dumps.append(emptylines)
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


# pylint: disable-next=too-many-branches,too-many-locals,too-many-statements
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
    dumps: list[list[ThemeRef | ThemeStr]] = []
    indent: int = deep_get(cmtlib.cmtconfig, DictPath("Global#indent"), 2)
    is_json: bool = deep_get(kwargs, DictPath("json"), False)
    unfold_msg: bool = deep_get(kwargs, DictPath("unfold_msg"), False)

    if isinstance(lines, str):
        if is_json or (lines.startswith("{") and lines.rstrip().endswith("}") and unfold_msg):
            try:
                d = json.loads(lines)
                lines = [json_dumps(d)]
            except DecodeException:
                return format_none(lines)
        else:
            lines = [lines]
    elif isinstance(lines, dict):
        lines = [lines]

    generic_format = ThemeAttr("types", "generic")

    override_formatting: dict[str, ThemeAttr] = \
        deep_get(kwargs, DictPath("override_formatting"), {})

    if deep_get(kwargs, DictPath("raw"), False):
        override_formatting = {"__all": generic_format}

    yaml.add_representer(str, __str_representer)

    for i, obj in enumerate(lines):
        if isinstance(obj, dict):
            if is_json:
                split_dump = json.dumps(obj, indent=indent).splitlines()
            else:
                split_dump = yaml.dump(obj, default_flow_style=False,
                                       indent=indent, width=sys.maxsize).splitlines()
        else:
            # The type ignore below is necessary because of the way we pass data
            # to this function.
            split_dump = obj.splitlines()  # type: ignore[attr-defined]
        first = True
        if (split_dump and "\n" not in obj
                and split_dump[0].startswith("'") and split_dump[0].endswith("'")):
            split_dump[0] = split_dump[0][1:-1]

        for line in split_dump:
            truncated = False

            if len(line) >= 16384 - len(" [...] (Truncated)") - 1:
                line = line[0:16384 - len(" [...] (Truncated)") - 1]
                truncated = True
            # This allows us to use the yaml formatter for json too
            if first:
                first = False
                if line in ("|", "|-"):
                    continue
            if not line:
                continue

            kwargs["override_formatting"] = override_formatting
            tmpline: list[ThemeRef | ThemeStr] = []
            remnants: list[list[ThemeRef | ThemeStr]] = []
            tmpline, remnants = format_yaml_line(line, **kwargs)
            if truncated:
                tmpline += [ThemeStr(" [...] (Truncated)",
                            ThemeAttr("types", "yaml_key_error"))]
            dumps.append(tmpline)
            if remnants:
                dumps += remnants

        if i < len(lines) - 1:
            dumps.append([ThemeStr("", generic_format)])
            dumps.append([ThemeStr("", generic_format)])
            dumps.append([ThemeStr("", generic_format)])

    return dumps


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


KEY_HEADERS: tuple[str, ...] = (
    "-----BEGIN CERTIFICATE-----",
    "-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE REQUEST-----",
    "-----END CERTIFICATE REQUEST-----",
    "-----BEGIN PKCS7-----",
    "-----END PKCS7-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----END OPENSSH PRIVATE KEY-----",
    "-----BEGIN SSH2 PUBLIC KEY-----",
    "-----END SSH2 PUBLIC KEY-----",
    "-----BEGIN PUBLIC KEY-----",
    "-----END PUBLIC KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----END PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----END DSA PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----END RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----END EC PRIVATE KEY-----",
)


# pylint: disable=unused-argument
def format_cel(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    CEL formatter; returns the text with syntax highlighting for Common Expression Language.

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
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    for line in lines:
        if line in KEY_HEADERS:
            dumps.append([ThemeStr(line, ThemeAttr("types", "separator"))])
        else:
            dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])
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
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if isinstance(lines, str):
        lines = split_msg(lines)

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    mosquitto_variable_regex: re.Pattern[str] = re.compile(r"^(\S+)(\s)(.+)")

    for line in lines:
        # Is it whitespace?
        if not line.strip():
            dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])
            continue

        # Is it a comment?
        if line.startswith("#"):
            dumps.append([ThemeStr(line, ThemeAttr("types", "mosquitto_comment"))])
            continue

        # Is it a variable + value?
        tmp = mosquitto_variable_regex.match(line)
        if tmp is not None:
            variable = tmp[1]
            whitespace = tmp[2]
            value = tmp[3]
            tmpline: list[ThemeRef | ThemeStr] = [
                ThemeStr(variable, ThemeAttr("types", "mosquitto_variable")),
                ThemeStr(whitespace, ThemeAttr("types", "generic")),
                ThemeStr(value, ThemeAttr("types", "generic")),
            ]
            dumps.append(tmpline)
            continue

        # Unknown data; just append it unformatted
        dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])

    return dumps


# pylint: disable-next=too-many-branches
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
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    key_regex: re.Pattern[str] = re.compile(r"^(\s*)(#.*$|}|\S+|$)(.+;|.+{|)(\s*#.*$|)")

    for line in lines:
        dump: list[ThemeRef | ThemeStr] = []
        if not line.strip():
            if not dump:
                dump += [
                    ThemeStr("", ThemeAttr("types", "generic"))
                ]
            dumps.append(dump)
            continue

        # key {
        # key value[ value...];
        # key value[ value...] {
        tmp = key_regex.match(line)
        if tmp is not None:
            if tmp[1]:
                dump += [
                    ThemeStr(tmp[1], ThemeAttr("types", "generic")),  # whitespace
                ]
            if tmp[2]:
                if tmp[2] == "}":
                    dump += [
                        ThemeStr(tmp[2], ThemeAttr("types", "generic")),  # block end
                    ]
                elif tmp[2].startswith("#"):
                    dump += [
                        ThemeStr(tmp[2], ThemeAttr("types", "nginx_comment"))
                    ]
                else:
                    dump += [
                        ThemeStr(tmp[2], ThemeAttr("types", "nginx_key"))
                    ]
            if tmp[3]:
                dump += [
                    ThemeStr(tmp[3][:-1], ThemeAttr("types", "nginx_value")),
                    # block start / statement end
                    ThemeStr(tmp[3][-1:], ThemeAttr("types", "generic")),
                ]
            if tmp[4]:
                dump += [
                    ThemeStr(tmp[4], ThemeAttr("types", "nginx_comment"))
                ]
            dumps.append(dump)
        else:
            sys.exit(f"__format_nginx(): Could not match line={line}")
    return dumps


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
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
    dumps: list[list[ThemeRef | ThemeStr]] = []

    tag_open = False
    tag_named = False
    comment = False

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    escape_regex: re.Pattern[str] = re.compile(r"^(\s*)(&)(.+?)(;)(.*)")
    content_regex: re.Pattern[str] = re.compile(r"^(.*?)(<.*|&.*)")
    tag_open_regex: re.Pattern[str] = re.compile(r"^(\s*)(</|<!--|<\?|<)(.*)")
    tag_named_regex: re.Pattern[str] = re.compile(r"^(.+?)(\s*>|\s*\?>|\s*$|\s+.*)")
    tag_close_regex: re.Pattern[str] = re.compile(r"^(\s*)(/>|\?>|-->|--!>|>)(.*)")
    remainder_regex: re.Pattern[str] = \
        re.compile(r"^(\s*\S+?)(=|)(\"[^\"]+?\"|)(\s*$|\s*/>|\s*\?>|\s*-->|\s*>|\s+)(.*|)")

    i = 0

    # pylint: disable-next=too-many-nested-blocks
    for line in lines:
        tmpline: list[ThemeRef | ThemeStr] = []

        # Empty line
        if not line and not tmpline:
            tmpline = [
                ThemeStr("", ThemeAttr("types", "generic")),
            ]

        while line:
            before = line
            if not tag_open:
                # Are we opening a tag?
                tmp = tag_open_regex.match(line)
                if tmp is not None:
                    tag_open = True
                    tag_named = False

                    # Do not add 0-length "indentation"
                    if tmp[1]:
                        tmpline += [
                            ThemeStr(tmp[1], ThemeAttr("types", "xml_declaration")),
                        ]

                    if tmp[2] == "<?":
                        # declaration tags are implicitly named
                        tag_named = True
                        tmpline += [
                            ThemeStr(tmp[2], ThemeAttr("types", "xml_declaration")),
                        ]
                        line = tmp[3]
                        continue

                    if tmp[2] == "<!--":
                        comment = True
                        tmpline += [
                            ThemeStr(tmp[2], ThemeAttr("types", "xml_comment")),
                        ]
                        line = tmp[3]
                        continue

                    tmpline += [
                        ThemeStr(tmp[2], ThemeAttr("types", "xml_tag")),
                    ]
                    line = tmp[3]
                    continue

                # Is this an escape?
                tmp = escape_regex.match(line)
                if tmp is not None:
                    tmpline += [
                        ThemeStr(tmp[1], ThemeAttr("types", "xml_content")),
                        ThemeStr(tmp[2], ThemeAttr("types", "xml_escape")),
                        ThemeStr(tmp[3], ThemeAttr("types", "xml_escape_data")),
                        ThemeStr(tmp[4], ThemeAttr("types", "xml_escape")),
                    ]
                    line = tmp[5]
                    continue

                # Nope, it is content; split to first & or <
                tmp = content_regex.match(line)
                if tmp is not None:
                    tmpline += [
                        ThemeStr(tmp[1], ThemeAttr("types", "xml_content")),
                    ]
                    line = tmp[2]
                else:
                    tmpline += [
                        ThemeStr(line, ThemeAttr("types", "xml_content")),
                    ]
                    line = ""
            else:
                # Are we closing a tag?
                tmp = tag_close_regex.match(line)
                if tmp is not None:
                    # Do not add 0-length "indentation"
                    if tmp[1]:
                        tmpline += [
                            ThemeStr(tmp[1], ThemeAttr("types", "xml_comment")),
                        ]

                    # > is ignored within comments
                    if tmp[2] == ">" and comment or tmp[2] == "-->":
                        tmpline += [
                            ThemeStr(tmp[2], ThemeAttr("types", "xml_comment")),
                        ]
                        line = tmp[3]
                        if tmp[2] == "-->":
                            comment = False
                            tag_open = False
                        continue

                    if tmp[2] == "?>":
                        tmpline += [
                            ThemeStr(tmp[2], ThemeAttr("types", "xml_declaration")),
                        ]
                        line = tmp[3]
                        tag_open = False
                        continue

                    tmpline += [
                        ThemeStr(tmp[2], ThemeAttr("types", "xml_tag")),
                    ]
                    line = tmp[3]
                    tag_open = False
                    continue

                if not tag_named and not comment:
                    # Is this either "[<]tag", "[<]tag ", "[<]tag>" or "[<]tag/>"?
                    tmp = tag_named_regex.match(line)
                    if tmp is not None:
                        tmpline += [
                            ThemeStr(tmp[1], ThemeAttr("types", "xml_tag")),
                        ]
                        line = tmp[2]
                        tag_named = True
                        continue
                else:
                    # This *should* match all remaining cases
                    tmp = remainder_regex.match(line)
                    if tmp is None:
                        raise SyntaxError(f"XML syntax highlighter failed to parse {line}")

                    if comment:
                        tmpline += [
                            ThemeStr(tmp[1], ThemeAttr("types", "xml_comment")),
                            ThemeStr(tmp[2], ThemeAttr("types", "xml_comment")),
                            ThemeStr(tmp[3], ThemeAttr("types", "xml_comment")),
                        ]
                    else:
                        tmpline += [
                            ThemeStr(tmp[1], ThemeAttr("types", "xml_attribute_key")),
                        ]

                        if tmp[2]:
                            tmpline += [
                                ThemeStr(tmp[2], ThemeAttr("types", "xml_content")),
                                ThemeStr(tmp[3], ThemeAttr("types", "xml_attribute_value")),
                            ]
                    line = tmp[4] + tmp[5]
                    continue
            if before == line:
                raise SyntaxError(f"XML syntax highlighter parse failure at line #{i + 1}:\n"
                                  "{lines}\n"
                                  "Parsed fragments of line:\n"
                                  "{tmpline}\n"
                                  "Unparsed fragments of line:\n"
                                  "{line}")

        dumps.append(tmpline)
        i += 1

    return dumps


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
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if isinstance(lines, str):
        lines = split_msg(lines)

    block = False

    for line in lines:
        if not block and line == "Traceback (most recent call last):":
            dumps.append([
                ThemeStr(line, ThemeAttr("logview", "severity_error"))
            ])
            block = True
            continue
        if block:
            tmp = re.match(r"^(\s+File \")(.+?)(\", line )(\d+)(, in )(.*)", line)
            if tmp is not None:
                dumps.append([
                    ThemeStr(tmp[1], ThemeAttr("logview", "severity_info")),
                    ThemeStr(tmp[2], ThemeAttr("types", "path")),
                    ThemeStr(tmp[3], ThemeAttr("logview", "severity_info")),
                    ThemeStr(tmp[4], ThemeAttr("types", "lineno")),
                    ThemeStr(tmp[5], ThemeAttr("logview", "severity_info")),
                    ThemeStr(tmp[6], ThemeAttr("types", "path"))
                ])
                continue
            tmp = re.match(r"(^\S+?Error:|Exception:|GeneratorExit:|"
                           r"KeyboardInterrupt:|StopIteration:|StopAsyncIteration:|"
                           r"SystemExit:|socket.gaierror:)( .*)", line)
            if tmp is not None:
                dumps.append([
                    ThemeStr(tmp[1], ThemeAttr("logview", "severity_error")),
                    ThemeStr(tmp[2], ThemeAttr("logview", "severity_info"))
                ])
                block = False
                continue
        dumps.append([ThemeStr(line, ThemeAttr("logview", "severity_info"))])
    return dumps


# pylint: disable-next=too-many-branches
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
    # Necessary improvements:
    # * Instead of only checking for lines that end with a comment for key = value,
    #   and for full comment lines, check for lines that end with a comment
    #   in any situation (except multiline). Split out the comment and add it last.
    # * Handle quoting and escaping of quotes; \''' should not end a multiline, for instance.
    # * XXX: should we highlight key=value for inline tables? Probably not
    # * XXX: should we highlight different types (integer, string, etc.)? Almost certainly not.
    dumps: list[list[ThemeRef | ThemeStr]] = []

    multiline_basic = False
    multiline_literal = False

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    key_value_regex: re.Pattern[str] = re.compile(r"^(\s*)(\S+)(\s*=\s*)(\S+)")
    comment_end_regex: re.Pattern[str] = re.compile(r"^(.*)(#.*)")

    tmpline: list[ThemeRef | ThemeStr] = []

    for line in lines:
        if not line:
            continue

        if multiline_basic or multiline_literal:
            tmpline += [
                ThemeStr(line, ThemeAttr("types", "toml_value")),
            ]
            dumps.append(tmpline)
            if multiline_basic and line.lstrip(" ").endswith("\"\"\""):
                multiline_basic = False
            elif multiline_literal and line.lstrip(" ").endswith("'''"):
                multiline_literal = False
            continue

        tmpline = []
        if line.lstrip().startswith("#"):
            tmpline += [
                ThemeStr(line, ThemeAttr("types", "toml_comment")),
            ]
            dumps.append(tmpline)
            continue

        if line.lstrip().startswith("[") and line.rstrip(" ").endswith("]"):
            tmpline += [
                ThemeStr(line, ThemeAttr("types", "toml_table")),
            ]

            dumps.append(tmpline)
            continue

        tmp = key_value_regex.match(line)
        if tmp is not None:
            comment = ""
            indentation = tmp[1]
            key = tmp[2]
            separator = tmp[3]
            value = tmp[4]
            if value.rstrip(" ").endswith("\"\"\""):
                multiline_basic = True
            elif value.rstrip(" ").endswith("'''"):
                multiline_literal = True
            else:
                # Does this line end with a comment?
                tmp = comment_end_regex.match(value)
                if tmp is not None:
                    value = tmp[1]
                    comment = tmp[2]
            tmpline += [
                ThemeStr(f"{indentation}", ThemeAttr("types", "generic")),
                ThemeStr(f"{key}", ThemeAttr("types", "toml_key")),
                ThemeStr(f"{separator}", ThemeAttr("types", "toml_key_separator")),
                ThemeStr(f"{value}", ThemeAttr("types", "toml_value")),
            ]
            if comment:
                tmpline += [
                    ThemeStr(f"{comment}", ThemeAttr("types", "toml_comment")),
                ]
            dumps.append(tmpline)
        # dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])
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
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    key_value_regex: re.Pattern[str] = re.compile(r"^(\s*)(\S+)(\s*=\s*)(\S+)")

    for line in lines:
        tmpline: list[ThemeRef | ThemeStr] = []
        if line.lstrip().startswith(("#", ";")):
            tmpline = [
                ThemeStr(line, ThemeAttr("types", "ini_comment")),
            ]
        elif line.lstrip().startswith("[") and line.rstrip().endswith("]"):
            tmpline = [
                ThemeStr(line, ThemeAttr("types", "ini_section")),
            ]
        else:
            tmp = key_value_regex.match(line)
            if tmp is not None:
                indentation = tmp[1]
                key = tmp[2]
                separator = tmp[3]
                value = tmp[4]

                if indentation:
                    tmpline = [
                        ThemeStr(f"{indentation}", ThemeAttr("types", "generic")),
                    ]
                else:
                    tmpline = []

                tmpline += [
                    ThemeStr(f"{key}", ThemeAttr("types", "ini_key")),
                    ThemeStr(f"{separator}", ThemeAttr("types", "ini_key_separator")),
                    ThemeStr(f"{value}", ThemeAttr("types", "ini_value")),
                ]
        dumps.append(tmpline)
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
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    host_keytype_key_regex: re.Pattern[str] = re.compile(r"^(\S+)(\s+)(\S+)(\s+)(\S+)")

    for line in lines:
        tmpline: list[ThemeRef | ThemeStr] = []
        if line.lstrip().startswith(("#", ";")):
            tmpline = [
                ThemeStr(line, ThemeAttr("types", "known_hosts_comment")),
            ]
        else:
            tmp = host_keytype_key_regex.match(line)
            if tmp is not None:
                hostname = tmp[1]
                whitespace1 = tmp[2]
                crypto = tmp[3]
                whitespace2 = tmp[4]
                key = tmp[5]

                tmpline = [
                    ThemeStr(f"{hostname}", ThemeAttr("types", "known_hosts_hostname")),
                    ThemeStr(whitespace1, ThemeAttr("types", "generic")),
                    ThemeStr(f"{crypto}", ThemeAttr("types", "known_hosts_crypto")),
                    ThemeStr(whitespace2, ThemeAttr("types", "generic")),
                    ThemeStr(f"{key}", ThemeAttr("types", "known_hosts_key")),
                ]
        dumps.append(tmpline)
    return dumps


# (startswith, endswith, formatter)
formatter_mapping: tuple[tuple[tuple[str, ...], tuple[str, ...], Callable], ...] = (
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
    (("mosquitto",), ("",), format_mosquitto),
    (("NGINX",), ("NGINX",), format_nginx),
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
