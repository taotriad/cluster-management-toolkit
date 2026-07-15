#! /usr/bin/env python3

# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

# unit-tests for formatters.py

import builtins
from datetime import datetime
import sys
from typing import Any, cast
from collections.abc import Callable
import pygments
import yaml

from clustermanagementtoolkit import cmtio_yaml

from clustermanagementtoolkit.cmtpaths import DEFAULT_THEME_FILE

from clustermanagementtoolkit.cmttypes import deep_get, DictPath

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint, init_ansithemeprint

from clustermanagementtoolkit import formatters

from clustermanagementtoolkit.curses_helper import ThemeAttr, ThemeRef, ThemeStr
from clustermanagementtoolkit.curses_helper import read_theme, themearray_to_string

pygments_version: list[str] = pygments.__version__.split(".")

real_import: Callable | None = None  # pylint: disable=invalid-name

import_override: dict = {}


def override_import(name: str, *args: list[Any], **kwargs: Any):
    global real_import
    retval, exception = import_override.get(name, (None, None))
    if exception:
        raise exception
    if retval:
        return retval
    real_import = cast(Callable, real_import)
    return real_import(name, *args, **kwargs)


def yaml_dump(data: Any, base_indent: int = 4) -> str:
    result = ""
    dump = yaml.dump(data)
    for line in dump.splitlines():
        result += f"{' '.ljust(base_indent)}{line}\n"
    return result


def test_json_dumps(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = cmtio_yaml.json_dumps

    if result:
        # Indata format:
        # (dict, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ({"foo": "bar", "bar": 1}, "{\n  \"foo\": \"bar\",\n  \"bar\": 1\n}", None),
        )

        for indata, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "          output:\n" \
                              f"{yaml_dump(tmp, base_indent=17)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_render_markdown(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.render_markdown

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # GitHub header, bold, italics, and emoji tag; tag NOT replaced.
            (["# Header 1",
              "A **bold** message.",
              "",
              "## Header 2",
              "An *italicized* message with a recycling emoji :recycle:"],
             {"use_github_tags": False},
             [
                 [ThemeStr("Header 1", ThemeAttr("types", "markdown_header_1"), False)],
                 [ThemeStr("A ", ThemeAttr("types", "generic"), False),
                  ThemeStr("bold", ThemeAttr("types", "markdown_bold"), False),
                  ThemeStr(" message.", ThemeAttr("types", "generic"), False)],
                 [],
                 [ThemeStr("Header 2", ThemeAttr("types", "markdown_header_2"), False)],
                 [ThemeStr("An ", ThemeAttr("types", "generic"), False),
                  ThemeStr("italicized", ThemeAttr("types", "markdown_italics"), False),
                  ThemeStr(" message with a recycling emoji :recycle:",
                           ThemeAttr("types", "generic"), False)]],
             None),
            # GitHub header, bold, italics, and emoji tag; tag replaced.
            (["# Header 1",
              "A **bold** message.",
              "",
              "## Header 2",
              "An *italicized* message with a recycling emoji :recycle:."],
             {},
             [
                 [ThemeStr("Header 1", ThemeAttr("types", "markdown_header_1"), False)],
                 [ThemeStr("A ", ThemeAttr("types", "generic"), False),
                  ThemeStr("bold", ThemeAttr("types", "markdown_bold"), False),
                  ThemeStr(" message.", ThemeAttr("types", "generic"), False)],
                 [],
                 [ThemeStr("Header 2", ThemeAttr("types", "markdown_header_2"), False)],
                 [ThemeStr("An ", ThemeAttr("types", "generic"), False),
                  ThemeStr("italicized", ThemeAttr("types", "markdown_italics"), False),
                  ThemeStr(" message with a recycling emoji ♻️.",
                           ThemeAttr("types", "generic"), False)]],
             None),
            # GitHub alert
            (["> [!WARNING]",
              "> This is a test warning."],
             {},
             [
                [ThemeStr("┃ ", ThemeAttr("main", "highlight"), False),
                 ThemeStr("⚠️ ", ThemeAttr("types", "generic"), False),
                 ThemeStr(" Warning", ThemeAttr("types", "markdown_warning"), False)],
                [ThemeStr("┃ ", ThemeAttr("main", "highlight"), False),
                 ThemeStr("This is a test warning.",
                          ThemeAttr("types", "markdown_italics"), False)]],
             None),
            # GitHub alert, tags not replaced
            (["> [!WARNING]",
              "> This is a test warning."],
             {"use_github_tags": False},
             [
                [ThemeStr("┃ ", ThemeAttr("main", "highlight"), False),
                 ThemeStr("[!WARNING]", ThemeAttr("types", "markdown_italics"), False)],
                [ThemeStr("┃ ", ThemeAttr("main", "highlight"), False),
                 ThemeStr("This is a test warning.",
                          ThemeAttr("types", "markdown_italics"), False)]],
             None),
            # Table with delimiters on the outside
            (["|A simple|Table  |",
              "|--------|-----|",
              "|some data !!|foo|"],
             {},
             [
                [ThemeStr("┌────────────┬─────┐", ThemeAttr("types", "generic"))],
                [ThemeStr("│", ThemeAttr("types", "generic")),
                 ThemeStr("A simple", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("    │", ThemeAttr("types", "generic")),
                 ThemeStr("Table", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("│", ThemeAttr("types", "generic"))],
                [ThemeStr("├────────────┼─────┤", ThemeAttr("types", "generic"))],
                [ThemeStr("│some data !!│foo  │", ThemeAttr("types", "generic"))],
                [ThemeStr("└────────────┴─────┘", ThemeAttr("types", "generic"))]],
             None),
            # Table without delimiters on the outside
            (["A simple|Table",
              "--------|-----",
              "some data !!|foo"],
             {},
             [
                [ThemeStr("┌────────────┬─────┐", ThemeAttr("types", "generic"))],
                [ThemeStr("│", ThemeAttr("types", "generic")),
                 ThemeStr("A simple", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("    │", ThemeAttr("types", "generic")),
                 ThemeStr("Table", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("│", ThemeAttr("types", "generic"))],
                [ThemeStr("├────────────┼─────┤", ThemeAttr("types", "generic"))],
                [ThemeStr("│some data !!│foo  │", ThemeAttr("types", "generic"))],
                [ThemeStr("└────────────┴─────┘", ThemeAttr("types", "generic"))]],
             None),
            # Table with formatting
            (["|Table With|Formatted Fields|",
              "|--------|-----|",
              "|No formatting| **formatting** no formatting|"],
             {},
             [
                [ThemeStr("┌─────────────┬────────────────────────┐",
                          ThemeAttr("types", "generic"))],
                [ThemeStr("│", ThemeAttr("types", "generic")),
                 ThemeStr("Table With", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("   │", ThemeAttr("types", "generic")),
                 ThemeStr("Formatted Fields", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("        │", ThemeAttr("types", "generic"))],
                [ThemeStr("├─────────────┼────────────────────────┤",
                          ThemeAttr("types", "generic"))],
                [ThemeStr("│No formatting│", ThemeAttr("types", "generic")),
                 ThemeStr("formatting", ThemeAttr("types", "markdown_bold")),
                 ThemeStr(" no formatting│", ThemeAttr("types", "generic"))],
                [ThemeStr("└─────────────┴────────────────────────┘",
                          ThemeAttr("types", "generic"))]],
             None),
            # Table with pre-formatted data containing | characters
            (["|Table With|Preformatted Data|",
              "|--------|-----|",
              "|No formatting| `cat foo | grep bar` |"],
             {},
             [
                [ThemeStr("┌─────────────┬──────────────────┐",
                          ThemeAttr("types", "generic"))],
                [ThemeStr("│", ThemeAttr("types", "generic")),
                 ThemeStr("Table With", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("   │", ThemeAttr("types", "generic")),
                 ThemeStr("Preformatted Data", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr(" │", ThemeAttr("types", "generic"))],
                [ThemeStr("├─────────────┼──────────────────┤",
                          ThemeAttr("types", "generic"))],
                [ThemeStr("│No formatting│", ThemeAttr("types", "generic")),
                 ThemeStr("cat foo | grep bar", ThemeAttr("types", "markdown_code")),
                 ThemeStr("│", ThemeAttr("types", "generic"))],
                [ThemeStr("└─────────────┴──────────────────┘",
                          ThemeAttr("types", "generic"))]],
             None),
            # Table with pre-formatted data containing | characters; raw
            (["|Table With|Preformatted Data|",
              "|--------|-----|",
              "|No formatting| `cat foo | grep bar` |"],
             {"raw": True},
             [
                [ThemeStr("|Table With|Preformatted Data|", ThemeAttr("types", "generic"))],
                [ThemeStr("|--------|-----|", ThemeAttr("types", "generic"))],
                [ThemeStr("|No formatting| `cat foo | grep bar` |",
                          ThemeAttr("types", "generic"))]],
             None),
            # A table header without separator
            ("|Col1|Col2|\n"
             "Not a table",
             {},
             [
                 [ThemeStr("|Col1|Col2|", ThemeAttr("types", "generic"))],
                 [ThemeStr("Not a table", ThemeAttr("types", "generic"))]],
             None),
            # A table without data
            (["|Table without data|Col 2|",
              "|--------|-----|"],
             {},
             [
                [ThemeStr("|Table without data|Col 2|", ThemeAttr("types", "generic"))],
                [ThemeStr("|--------|-----|", ThemeAttr("types", "generic"))]],
             None),
            # A table without data, v2
            (["|Table without data|Col 2|",
              "|--------|-----|",
              "Not a table"],
             {},
             [
                [ThemeStr("|Table without data|Col 2|", ThemeAttr("types", "generic"))],
                [ThemeStr("|--------|-----|", ThemeAttr("types", "generic"))],
                [ThemeStr("Not a table", ThemeAttr("types", "generic"))]],
             None),
            # A table with one line of data
            (["|Table without data|Col 2|",
              "|--------|-----|",
              "|data 1|data 2|",
              "Not a part of the table"],
             {},
             [
                [ThemeStr("┌──────────────────┬──────┐", ThemeAttr("types", "generic"))],
                [ThemeStr("│", ThemeAttr("types", "generic")),
                 ThemeStr("Table without data", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("│", ThemeAttr("types", "generic")),
                 ThemeStr("Col 2", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr(" │", ThemeAttr("types", "generic"))],
                [ThemeStr("├──────────────────┼──────┤", ThemeAttr("types", "generic"))],
                [ThemeStr("│data 1            │data 2│", ThemeAttr("types", "generic"))],
                [ThemeStr("└──────────────────┴──────┘", ThemeAttr("types", "generic"))],
                [ThemeStr("Not a part of the table", ThemeAttr("types", "generic"))]],
             None),
            # A table with mismatching column count
            (["|Broken table|Col 2|",
              "|--------|-----|",
              "|data 1|data 2|data 3|"],
             {},
             [
                [ThemeStr("|Broken table|Col 2|", ThemeAttr("types", "generic"))],
                [ThemeStr("|--------|-----|", ThemeAttr("types", "generic"))],
                [ThemeStr("|data 1|data 2|data 3|", ThemeAttr("types", "generic"))]],
             None),
            # A table with mismatching deliminators
            (["|A simple|Table|",
              "|--------|-----|",
              "|data 1|data 2",
              "data 3|data 4|"],
             {},
             [
                [ThemeStr("┌────────┬──────┐", ThemeAttr("types", "generic"))],
                [ThemeStr("│", ThemeAttr("types", "generic")),
                 ThemeStr("A simple", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr("│", ThemeAttr("types", "generic")),
                 ThemeStr("Table", ThemeAttr("types", "markdown_table_header")),
                 ThemeStr(" │", ThemeAttr("types", "generic"))],
                [ThemeStr("├────────┼──────┤", ThemeAttr("types", "generic"))],
                [ThemeStr("│data 1  │data 2│", ThemeAttr("types", "generic"))],
                [ThemeStr("│data 3  │data 4│", ThemeAttr("types", "generic"))],
                [ThemeStr("└────────┴──────┘", ThemeAttr("types", "generic"))]],
              None),
            # Markdown bullets, lists, and checklists
            (["*Foo",
              "",
              "* Foo",
              "* Bar",
              "* Baz",
              "",
              "* [ ] Unselected",
              "* [x] Selected"],
             {},
             [
                [ThemeStr("*Foo", ThemeAttr("types", "generic"))],
                [],
                [ThemeStr("•", ThemeAttr("types", "genericbullet"), False),
                 ThemeStr(" Foo", ThemeAttr("types", "generic"), False)],
                [ThemeStr("•", ThemeAttr("types", "genericbullet"), False),
                 ThemeStr(" Bar", ThemeAttr("types", "generic"), False)],
                [ThemeStr("•", ThemeAttr("types", "genericbullet"), False),
                 ThemeStr(" Baz", ThemeAttr("types", "generic"), False)],
                [],
                [ThemeStr("•", ThemeAttr("types", "genericbullet"), False),
                 ThemeStr(" ", ThemeAttr("types", "generic"), False),
                 ThemeStr("⬜", ThemeAttr("main", "highlight"), False),
                 ThemeStr(" Unselected", ThemeAttr("types", "generic"), False)],
                [ThemeStr("•", ThemeAttr("types", "genericbullet"), False),
                 ThemeStr(" ", ThemeAttr("types", "generic"), False),
                 ThemeStr("✅", ThemeAttr("main", "highlight"), False),
                 ThemeStr(" Selected", ThemeAttr("types", "generic"), False)]],
             None),
            # Headers and subheaders
            (["# H0",
              "",
              "## H1",
              "",
              "### H2",
              "",
              "#### H3"],
             {},
             [
                [ThemeStr("H0", ThemeAttr("types", "markdown_header_1"), False)],
                [],
                [ThemeStr("H1", ThemeAttr("types", "markdown_header_2"), False)],
                [],
                [ThemeStr("H2", ThemeAttr("types", "markdown_header_3"), False)],
                [],
                [ThemeStr("H3", ThemeAttr("types", "markdown_bold"), False)]],
             None),
            # ```block quote```
            (["Something else first",
              "",
              "```",
              "code",
              "more code",
              "```"],
             {},
             [
                [ThemeStr("Something else first", ThemeAttr("types", "generic"), False)],
                [],
                [ThemeStr("code", ThemeAttr("types", "markdown_code"), False)],
                [ThemeStr("more code", ThemeAttr("types", "markdown_code"), False)]],
             None),
            # block
            (["> Foo",
              "> Bar",
              "> Baz"],
             {},
             [
                [ThemeStr("┃ ", ThemeAttr("main", "highlight"), False),
                 ThemeStr("Foo", ThemeAttr("types", "markdown_italics"), False)],
                [ThemeStr("┃ ", ThemeAttr("main", "highlight"), False),
                 ThemeStr("Bar", ThemeAttr("types", "markdown_italics"), False)],
                [ThemeStr("┃ ", ThemeAttr("main", "highlight"), False),
                 ThemeStr("Baz", ThemeAttr("types", "markdown_italics"), False)]],
             None),
            # #reference and @mention
            (["Issue #0123 (fixed by @foo)",
              "#0124: Another issue"],
             {},
             [
                [ThemeStr("Issue ", ThemeAttr("types", "generic"), False),
                 ThemeStr("#0123", ThemeAttr("types", "markdown_italics"), False),
                 ThemeStr(" (fixed by ", ThemeAttr("types", "generic"), False),
                 ThemeStr("@foo", ThemeAttr("types", "markdown_italics"), False),
                 ThemeStr(")", ThemeAttr("types", "generic"), False)],
                [ThemeStr("#0124:", ThemeAttr("types", "markdown_italics"), False),
                 ThemeStr(" Another issue", ThemeAttr("types", "generic"), False)]],
             None),
            # Numbered list
            (["1. Foo",
              "1. Bar",
              "1. Baz"],
             {},
             [
                [ThemeStr('1.', ThemeAttr('main', 'numbered_index'), False),
                 ThemeStr(' Foo', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('2.', ThemeAttr('main', 'numbered_index'), False),
                 ThemeStr(' Bar', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('3.', ThemeAttr('main', 'numbered_index'), False),
                 ThemeStr(' Baz', ThemeAttr('types', 'generic'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            # This is only used for the output; do not pass it as indata
            indata_quoted = indata_quoted.replace("\n", "\\n")
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {repr(tmp)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_binary(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_binary

    try:
        if (tmp := fun("\xff\x3f")) != [[ThemeStr("Binary file; cannot view",
                                                  ThemeAttr("types", "generic"))]]:
            message = f"{fun.__name__}() did not yield expected result:\n" \
                      f"           input: <binary>\n" \
                      "          output:\n" \
                      f"{themearray_to_string(tmp)}"
            result = False
    except Exception as e:
        message = f"{fun.__name__}() did not yield expected result:\n" \
                  f"           input: <binary>\n" \
                  f"       exception: {type(e)}"
        result = False
    return message, result


def test_format_none(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_none

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("Not reformatted",
             {},
             [
                [ThemeStr("Not reformatted", ThemeAttr("types", "generic"))]],
             None),
            (["Not reformatted"],
             {},
             [
                [ThemeStr("Not reformatted", ThemeAttr("types", "generic"))]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              "          output:\n" \
                              f"{themearray_to_string(tmp)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_ansible_line(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_ansible_line

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("Some random output from Ansible", {},
             [
                 ThemeStr("Some random output from Ansible", ThemeAttr("types", "generic"))],
             None),
            ("Another random output from Ansible",
             {"override_formatting": {"__all": ThemeAttr("types", "value")}},
             [
                 ThemeStr("Another random output from Ansible", ThemeAttr("types", "value"))],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              "          output:\n" \
                              f"{themearray_to_string(tmp)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_diff_line(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_diff_line

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("+++ a", {}, [
                ThemeStr("+++ a",
                         ThemeAttr("logview", "severity_diffheader"))],
             None),
            ("--- b", {}, [
                ThemeStr("--- b",
                         ThemeAttr("logview", "severity_diffheader"))],
             None),
            ("@@ -16,7 +16,7 @@ import errno", {}, [
                ThemeStr("@@ -16,7 +16,7 @@ import errno",
                         ThemeAttr("logview", "severity_diffatat"))],
             None),
            ("+ formatter_mapping = (", {}, [
                ThemeStr("+ formatter_mapping = (",
                         ThemeAttr("logview", "severity_diffplus"))],
             None),
            ("- formatter_mapping = (", {}, [
                ThemeStr("- formatter_mapping = (",
                         ThemeAttr("logview", "severity_diffminus"))],
             None),
            ("  formatter_mapping = (", {}, [
                ThemeStr("  formatter_mapping = (",
                         ThemeAttr("logview", "severity_diffsame"))],
             None),
            ("  overridden formatting", {
                "override_formatting": {"__all": ThemeAttr("types", "generic")}}, [
                ThemeStr("  overridden formatting",
                         ThemeAttr("types", "generic"))],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_yaml_line(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_yaml_line

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("# A comment", {}, ([
                ThemeStr("# A comment", ThemeAttr("types", "yaml_comment"))],
             []), None),
            ("# A comment", {"override_formatting": {"__all": ThemeAttr("types", "generic")}}, ([
                ThemeStr("# A comment", ThemeAttr("types", "generic"))],
             []), None),
            ("    # Indented comment", {}, ([
                ThemeStr("    # Indented comment", ThemeAttr("types", "yaml_comment"))],
             []), None),
            ("key: value", {}, ([
                ThemeStr("key", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("value", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("\"key\": \"value\"", {}, ([
                ThemeStr("\"key\"", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("\"value\"", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("\"config\": \"value1\"\\n\"value2\"\\n\"value3\"",
             {"expand_newline_fields": ("config",)}, ([
                 ThemeStr("\"config\"", ThemeAttr("types", "yaml_key")),
                 ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                 ThemeStr("\"value1\"", ThemeAttr("types", "yaml_value")),
             ], [
                [ThemeStr("           ", ThemeAttr("types", "yaml_key"), False),
                 ThemeStr("\"value2\"", ThemeAttr("types", "yaml_value"), False)],
                [ThemeStr("           ", ThemeAttr("types", "yaml_key"), False),
                 ThemeStr("\"value3\"", ThemeAttr("types", "yaml_value"), False)],
             ]), None),
            ("\"key\": \"\033[0;4;37mvalue\"", {"value_strip_ansicodes": True}, ([
                ThemeStr("\"key\"", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("\"value\"", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("\"key\": \"value\"", {}, ([
                ThemeStr("\"key\"", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("\"value\"", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("key: &define", {}, ([
                ThemeStr("key", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("&", ThemeAttr("types", "yaml_reference")),
                ThemeStr("define", ThemeAttr("types", "yaml_anchor"))],
             []), None),
            ("key: &define '#112233'", {}, ([
                ThemeStr("key", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("&", ThemeAttr("types", "yaml_reference")),
                ThemeStr("define", ThemeAttr("types", "yaml_anchor")),
                ThemeStr(" '#112233'", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("key: *define", {}, ([
                ThemeStr("key", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("*", ThemeAttr("types", "yaml_reference")),
                ThemeStr("define", ThemeAttr("types", "yaml_anchor"))],
             []), None),
            ("key:", {"override_formatting": {"key": {"key": ThemeAttr("types", "generic")}}}, ([
                ThemeStr("key", ThemeAttr("types", "generic")),
                ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
             []), None),
            ("key: {", {}, ([
                ThemeStr("key", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("{", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("key: {", {}, ([
                ThemeStr("key", ThemeAttr("types", "yaml_key")),
                ThemeStr(": ", ThemeAttr("types", "yaml_key_separator")),
                ThemeStr("{", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("}", {}, ([
                ThemeStr("}", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("- value", {}, ([
                ThemeStr("", ThemeAttr("types", "generic")),
                ThemeRef("separators", "yaml_list"),
                ThemeStr("value", ThemeAttr("types", "yaml_value"))],
             []), None),
            ("- key:", {}, ([
                ThemeStr("", ThemeAttr("types", "generic")),
                ThemeRef("separators", "yaml_list"),
                ThemeStr("key", ThemeAttr("types", "yaml_key")),
                ThemeStr(':', ThemeAttr('types', 'yaml_key_separator'), False)],
             []), None),
            ("- key:", {"override_formatting": "a"}, None, TypeError),
            ('  "error": "please install istio or disable the istio ingress plugin: '
             'no matches for kind \\"Gateway\\" in version \\"networking.istio.io/v1beta1\\"",',
             {
                 "override_formatting": {
                     '"msg"': {
                         'key': ThemeAttr('types', 'yaml_key'),
                         'value': ThemeAttr('logview', 'severity_info')
                     },
                     '"message"': {
                         'key': ThemeAttr('types', 'yaml_key'),
                         'value': ThemeAttr('logview', 'severity_info')
                     },
                     '"err"': {
                         'key': ThemeAttr('types', 'yaml_key_error'),
                         'value': ThemeAttr('logview', 'severity_error')
                     },
                     '"error"': {
                         'key': ThemeAttr('types', 'yaml_key_error'),
                         'value': ThemeAttr('logview', 'severity_error')
                     }
                 },
                 'expand_newline_fields': ('config', 'errorVerbose',
                                           'stacktrace', 'status.message'),
             }, ([
                 ThemeStr('  "error"', ThemeAttr('types', 'yaml_key_error'), False),
                 ThemeStr(': ', ThemeAttr('types', 'yaml_key_separator'), False),
                 ThemeStr('"please install istio or disable the istio ingress plugin: '
                          'no matches for kind \\"Gateway\\" in version '
                          '\\"networking.istio.io/v1beta1\\"",',
                          ThemeAttr('logview', 'severity_error'), False)], []), None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    output, remnants = tmp
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


# Note: format_yaml handles both yaml and json, so there's a lot of overlap
# between this and reformat_json
def test_format_yaml(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_yaml

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("spec:\n"
             "  foo: 1\n"
             "  bar: 'baz'",
             {},
             [[ThemeStr("spec", ThemeAttr("types", "yaml_key")),
               ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
              [ThemeStr("  ", ThemeAttr("types", "generic")),
               ThemeStr("foo", ThemeAttr("types", "yaml_key")),
               ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
               ThemeStr(" ", ThemeAttr("types", "generic")),
               ThemeStr("1", ThemeAttr("types", "yaml_value"))],
              [ThemeStr("  ", ThemeAttr("types", "generic")),
               ThemeStr("bar", ThemeAttr("types", "yaml_key")),
               ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
               ThemeStr(" ", ThemeAttr("types", "generic")),
               ThemeStr("'", ThemeAttr("types", "yaml_value")),
               ThemeStr("baz", ThemeAttr("types", "yaml_value")),
               ThemeStr("'", ThemeAttr("types", "yaml_value"))]],
             None),
            (
                ["spec:",
                 "  foo: 1",
                 "  bar: 'baz'",
                 "metadata:",
                 "  name: data"],
                {},
                [[ThemeStr("spec", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("foo", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("1", ThemeAttr("types", "yaml_value"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("bar", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("'", ThemeAttr("types", "yaml_value")),
                  ThemeStr("baz", ThemeAttr("types", "yaml_value")),
                  ThemeStr("'", ThemeAttr("types", "yaml_value"))],
                 [ThemeStr("metadata", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("name", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("data", ThemeAttr("types", "yaml_value"))]],
                None),
            (
                ["spec:",
                 "  foo: 1",
                 "  bar: 'baz'"],
                {},
                [[ThemeStr("spec", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("foo", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("1", ThemeAttr("types", "yaml_value"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("bar", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("'", ThemeAttr("types", "yaml_value")),
                  ThemeStr("baz", ThemeAttr("types", "yaml_value")),
                  ThemeStr("'", ThemeAttr("types", "yaml_value"))]],
                None),
            (
                {
                    "spec": {
                        "foo": 1,
                        "bar": "baz",
                    },
                },
                {},
                [
                    [ThemeStr("spec", ThemeAttr("types", "yaml_key")),
                     ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
                    [ThemeStr("  ", ThemeAttr("types", "generic")),
                     ThemeStr("foo", ThemeAttr("types", "yaml_key")),
                     ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("1", ThemeAttr("types", "yaml_value"))],
                    [ThemeStr("  ", ThemeAttr("types", "generic")),
                     ThemeStr("bar", ThemeAttr("types", "yaml_key")),
                     ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("baz", ThemeAttr("types", "yaml_value"))]],
                None),
            (
                [
                    {
                        "spec": {
                            "foo": 1,
                            "bar": "baz",
                        },
                    },
                ],
                {}, [[ThemeStr("spec", ThemeAttr("types", "yaml_key")),
                      ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
                     [ThemeStr("  ", ThemeAttr("types", "generic")),
                      ThemeStr("foo", ThemeAttr("types", "yaml_key")),
                      ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                      ThemeStr(" ", ThemeAttr("types", "generic")),
                      ThemeStr("1", ThemeAttr("types", "yaml_value"))],
                     [ThemeStr("  ", ThemeAttr("types", "generic")),
                      ThemeStr("bar", ThemeAttr("types", "yaml_key")),
                      ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                      ThemeStr(" ", ThemeAttr("types", "generic")),
                      ThemeStr("baz", ThemeAttr("types", "yaml_value"))]],
                None),
            (
                [
                    {
                        "spec": {
                            "foo": 1,
                            "bar": "baz",
                        },
                    },
                    {
                        "metadata": {
                            "name": "data",
                        },
                    },
                ],
                {},
                [[ThemeStr("spec", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("foo", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("1", ThemeAttr("types", "yaml_value"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("bar", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("baz", ThemeAttr("types", "yaml_value"))],
                 [],
                 [ThemeStr("metadata", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("name", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("data", ThemeAttr("types", "yaml_value"))]],
                None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              f"         options: {options}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  f"         options: {options}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              f"         options: {options}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


# Note: format_yaml handles both yaml and json, so there's a lot of overlap
# between this and format_yaml
def test_reformat_json(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.reformat_json

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("{\n"
             "  \"spec\": {\n"
             "    \"foo\": 1,\n"
             "    \"bar\": \"baz\"\n"
             "  }\n"
             "}",
             {}, [[ThemeStr("{", ThemeAttr("types", "yaml_punctuation"))],
                  [ThemeStr("  ", ThemeAttr("types", "generic")),
                   ThemeStr("\"spec\"", ThemeAttr("types", "yaml_key")),
                   ThemeStr(":", ThemeAttr("types", "yaml_punctuation")),
                   ThemeStr(" ", ThemeAttr("types", "generic")),
                   ThemeStr("{", ThemeAttr("types", "yaml_punctuation"))],
                  [ThemeStr("    ", ThemeAttr("types", "generic")),
                   ThemeStr("\"foo\"", ThemeAttr("types", "yaml_key")),
                   ThemeStr(":", ThemeAttr("types", "yaml_punctuation")),
                   ThemeStr(" ", ThemeAttr("types", "generic")),
                   ThemeStr("1", ThemeAttr("types", "yaml_value")),
                   ThemeStr(",", ThemeAttr("types", "yaml_punctuation"))],
                  [ThemeStr("    ", ThemeAttr("types", "generic")),
                   ThemeStr("\"bar\"", ThemeAttr("types", "yaml_key")),
                   ThemeStr(":", ThemeAttr("types", "yaml_punctuation")),
                   ThemeStr(" ", ThemeAttr("types", "generic")),
                   ThemeStr("\"baz\"", ThemeAttr("types", "yaml_value"))],
                  [ThemeStr("  ", ThemeAttr("types", "generic")),
                   ThemeStr("}", ThemeAttr("types", "yaml_punctuation"))],
                  [ThemeStr("}", ThemeAttr("types", "yaml_punctuation"))]],
             None),
            (
                {
                    "spec": {
                        "foo": 1,
                        "bar": "baz"
                    }
                },
                {},
                [[ThemeStr("{", ThemeAttr("types", "yaml_punctuation"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("\"spec\"", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("{", ThemeAttr("types", "yaml_punctuation"))],
                 [ThemeStr("    ", ThemeAttr("types", "generic")),
                  ThemeStr("\"foo\"", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("1", ThemeAttr("types", "yaml_value")),
                  ThemeStr(",", ThemeAttr("types", "yaml_punctuation"))],
                 [ThemeStr("    ", ThemeAttr("types", "generic")),
                  ThemeStr("\"bar\"", ThemeAttr("types", "yaml_key")),
                  ThemeStr(":", ThemeAttr("types", "yaml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("\"baz\"", ThemeAttr("types", "yaml_value"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("}", ThemeAttr("types", "yaml_punctuation"))],
                 [ThemeStr("}", ThemeAttr("types", "yaml_punctuation"))]],
                None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              f"         options: {options}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  f"         options: {options}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              f"         options: {options}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_cel(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_cel

    if result:
        try:
            from pygments.lexers.cel import CELLexer  # noqa: F401
            cellexer_available: bool = True
        except ModuleNotFoundError:
            # CELLexer is available from Pygments 2.22
            cellexer_available = False

        if cellexer_available:
            # Indata format:
            # (lines, options, expected_result, expected_exception)
            testdata: tuple[Any, ...] = (
                ("self.minReplicas <= self.replicas && self.replicas <= self.maxReplicas",
                 {"raw": False},
                 [
                     [ThemeStr('self', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr('.', ThemeAttr('types', 'cel_punctuation'), False),
                      ThemeStr('minReplicas', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('<=', ThemeAttr('types', 'cel_operator'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('self', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr('.', ThemeAttr('types', 'cel_punctuation'), False),
                      ThemeStr('replicas', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('&&', ThemeAttr('types', 'cel_operator'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('self', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr('.', ThemeAttr('types', 'cel_punctuation'), False),
                      ThemeStr('replicas', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('<=', ThemeAttr('types', 'cel_operator'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('self', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr('.', ThemeAttr('types', 'cel_punctuation'), False),
                      ThemeStr('maxReplicas', ThemeAttr('types', 'cel_name'), False)]],
                 None),
                (["self.minReplicas <= self.replicas && self.replicas <= self.maxReplicas"],
                 {"raw": False},
                 [
                     [ThemeStr('self', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr('.', ThemeAttr('types', 'cel_punctuation'), False),
                      ThemeStr('minReplicas', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('<=', ThemeAttr('types', 'cel_operator'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('self', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr('.', ThemeAttr('types', 'cel_punctuation'), False),
                      ThemeStr('replicas', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('&&', ThemeAttr('types', 'cel_operator'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('self', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr('.', ThemeAttr('types', 'cel_punctuation'), False),
                      ThemeStr('replicas', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('<=', ThemeAttr('types', 'cel_operator'), False),
                      ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                      ThemeStr('self', ThemeAttr('types', 'cel_name'), False),
                      ThemeStr('.', ThemeAttr('types', 'cel_punctuation'), False),
                      ThemeStr('maxReplicas', ThemeAttr('types', 'cel_name'), False)]],
                 None),
                ("self.minReplicas <= self.replicas && self.replicas <= self.maxReplicas",
                 {"raw": True},
                 [
                     [ThemeStr("self.minReplicas <= self.replicas && "
                               "self.replicas <= self.maxReplicas",
                               ThemeAttr("types", "generic"))]],
                 None),
            )
        else:
            # Indata format:
            # (lines, options, expected_result, expected_exception)
            testdata = (
                ("self.minReplicas <= self.replicas && self.replicas <= self.maxReplicas",
                 {"raw": False},
                 [
                     [ThemeStr("self.minReplicas <= self.replicas && "
                               "self.replicas <= self.maxReplicas",
                               ThemeAttr("types", "generic"))]],
                 None),
                (["self.minReplicas <= self.replicas && self.replicas <= self.maxReplicas"],
                 {"raw": False},
                 [
                     [ThemeStr("self.minReplicas <= self.replicas && "
                               "self.replicas <= self.maxReplicas",
                               ThemeAttr("types", "generic"))]],
                 None),
                ("self.minReplicas <= self.replicas && self.replicas <= self.maxReplicas",
                 {"raw": True},
                 [
                     [ThemeStr("self.minReplicas <= self.replicas && "
                               "self.replicas <= self.maxReplicas",
                               ThemeAttr("types", "generic"))]],
                 None),
            )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {themearray_to_string(tmp)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_crt(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_crt

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("-----BEGIN CERTIFICATE-----\n"
             "FOOBARBAZ\n"
             "-----END CERTIFICATE-----",
             {},
             [
                 [ThemeStr("-----BEGIN CERTIFICATE-----", ThemeAttr("types", "separator"))],
                 [ThemeStr("FOOBARBAZ", ThemeAttr("types", "generic"))],
                 [ThemeStr("-----END CERTIFICATE-----", ThemeAttr("types", "separator"))]],
             None),
            (["-----BEGIN CERTIFICATE-----",
              "FOOBARBAZ",
              "-----END CERTIFICATE-----"],
             {},
             [
                 [ThemeStr("-----BEGIN CERTIFICATE-----", ThemeAttr("types", "separator"))],
                 [ThemeStr("FOOBARBAZ", ThemeAttr("types", "generic"))],
                 [ThemeStr("-----END CERTIFICATE-----", ThemeAttr("types", "separator"))]],
             None),
            ("-----BEGIN CERTIFICATE-----\n"
             "FOOBARBAZ\n"
             "-----END CERTIFICATE-----",
             {"raw": True},
             [
                 [ThemeStr("-----BEGIN CERTIFICATE-----", ThemeAttr("types", "generic"))],
                 [ThemeStr("FOOBARBAZ", ThemeAttr("types", "generic"))],
                 [ThemeStr("-----END CERTIFICATE-----", ThemeAttr("types", "generic"))]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {themearray_to_string(tmp)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_css(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_css

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ([
                "/* Comment */",
                "selector {",
                "  property: value",
                "}"],
             {},
             [
                 [ThemeStr("/* Comment */", ThemeAttr("types", "css_comment"))],
                 [ThemeStr("selector", ThemeAttr("types", "css_tag")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("{", ThemeAttr("types", "css_punctuation"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("property", ThemeAttr("types", "css_value")),
                  ThemeStr(":", ThemeAttr("types", "css_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("value", ThemeAttr("types", "css_value"))],
                 [ThemeStr("}", ThemeAttr("types", "css_punctuation"))]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_diff(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_diff

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ([
                "diff --git a/views/Pod.yaml b/views/Pod.yaml",
                "index f25df4175d43..67c040f46db1 100644",
                "--- a/views/Pod.yaml",
                "+++ b/views/Pod.yaml",
                "@@ -661,11 +661,13 @@ infoview:",
                "       helptext: \"Show container resources\"",
                "       title: \"Resources:\"",
                "       widget: \"windowwidget\"",
                "-      headers: [\"Request Type:\", \"Limits:\"]",
                "+      headers: [\"Request Type:\", \"Resource:\"]"],
             {},
             [
                [ThemeStr('diff --git a/views/Pod.yaml b/views/Pod.yaml',
                          ThemeAttr('logview', 'severity_diffheader'), False)],
                [ThemeStr('index f25df4175d43..67c040f46db1 100644',
                          ThemeAttr('logview', 'severity_diffheader'), False)],
                [ThemeStr('--- a/views/Pod.yaml',
                          ThemeAttr('logview', 'severity_diffminus'), False)],
                [ThemeStr('+++ b/views/Pod.yaml',
                          ThemeAttr('logview', 'severity_diffplus'), False)],
                [ThemeStr('@@ -661,11 +661,13 @@ infoview:',
                          ThemeAttr('logview', 'severity_diffatat'), False)],
                [ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('      helptext: "Show container resources"',
                          ThemeAttr('logview', 'severity_diffsame'), False)],
                [ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('      title: "Resources:"',
                          ThemeAttr('logview', 'severity_diffsame'), False)],
                [ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('      widget: "windowwidget"',
                          ThemeAttr('logview', 'severity_diffsame'), False)],
                [ThemeStr('-      headers: ["Request Type:", "Limits:"]',
                          ThemeAttr('logview', 'severity_diffminus'), False)],
                [ThemeStr('+      headers: ["Request Type:", "Resource:"]',
                          ThemeAttr('logview', 'severity_diffplus'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_dmesg(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_dmesg

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # pylint: disable-next=line-length
            (["[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-7.1.3+deb14-amd64 root=/dev/sda2 ro",  # noqa: E501
              # pylint: disable-next=line-length
              "[    0.000000] x86/split lock detection: #AC: crashing the kernel on kernel split_locks and warning on user-space split_locks",  # noqa: E501
              "[145440.611453] usb 3-3.3.2.1: device not accepting address 25, error -71"],
             {},
             [
                [ThemeStr('[    0.000000] ', ThemeAttr('types', 'dmesg_timestamp'), False),
                 ThemeStr('Command line:', ThemeAttr('types', 'dmesg_keyword'), False),
                 ThemeStr(' BOOT_IMAGE=/boot/vmlinuz-7.1.3+deb14-amd64 root=/dev/sda2 ro',
                          ThemeAttr('types', 'dmesg_string'), False)],
                [ThemeStr('[    0.000000] ', ThemeAttr('types', 'dmesg_timestamp'), False),
                 ThemeStr('x86/split lock detection:', ThemeAttr('types', 'dmesg_keyword'), False),
                 # pylint: disable-next=line-length
                 ThemeStr(' #AC: crashing the kernel on kernel split_locks and warning on user-space split_locks',  # noqa: E501
                          ThemeAttr('types', 'dmesg_bold'), False)],
                [ThemeStr('[145440.611453] ', ThemeAttr('types', 'dmesg_timestamp'), False),
                 ThemeStr('usb 3-3.3.2.1:', ThemeAttr('types', 'dmesg_keyword'), False),
                 ThemeStr(' device not accepting address 25, error -71',
                          ThemeAttr('types', 'dmesg_error'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_docker(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_docker

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # pylint: disable-next=line-length
            (["# A comment",
              "ARG GOLANG_VERSION=1.21",
              "FROM golang:${GOLANG_VERSION} as build",
              "ARG LOCAL_LICENSES",
              "WORKDIR /build",
              "COPY . .",
              "RUN make build && \\",
              "mkdir -p /install_root && \\",
              "if [ -z \"$LOCAL_LICENSES\" ]; then \\",
              "    make licenses; \\",
              "fi && \\",
              "cp -r licenses /install_root/ && \\",
              "cp bin/* /install_root",
              "LABEL description='A Dockerfile example'"],
             {},
             [
                [ThemeStr('# A comment', ThemeAttr('types', 'docker_comment'), False)],
                [ThemeStr('ARG', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('GOLANG_VERSION', ThemeAttr('types', 'docker_variable'), False),
                 ThemeStr('=', ThemeAttr('types', 'docker_operator'), False),
                 ThemeStr('1', ThemeAttr('types', 'docker_value'), False),
                 ThemeStr('.21', ThemeAttr('types', 'docker_string'), False)],
                [ThemeStr('FROM', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('golang:${GOLANG_VERSION}', ThemeAttr('types', 'docker_interpol'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('as', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('build', ThemeAttr('types', 'docker_interpol'), False)],
                [ThemeStr('ARG', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('LOCAL_LICENSES', ThemeAttr('types', 'docker_string'), False)],
                [ThemeStr('WORKDIR', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('/build', ThemeAttr('types', 'docker_interpol'), False)],
                [ThemeStr('COPY', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('.', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('.', ThemeAttr('types', 'docker_string'), False)],
                [ThemeStr('RUN', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('make', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('build', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('&&', ThemeAttr('types', 'docker_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('\\', ThemeAttr('types', 'docker_escape'), False)],
                [ThemeStr('mkdir', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('-p', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('/install_root', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('&&', ThemeAttr('types', 'docker_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('\\', ThemeAttr('types', 'docker_escape'), False)],
                [ThemeStr('if', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('[', ThemeAttr('types', 'docker_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('-z', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('"', ThemeAttr('types', 'docker_value'), False),
                 ThemeStr('$LOCAL_LICENSES', ThemeAttr('types', 'docker_variable'), False),
                 ThemeStr('"', ThemeAttr('types', 'docker_value'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr(']', ThemeAttr('types', 'docker_operator'), False),
                 ThemeStr(';', ThemeAttr('types', 'docker_punctuation'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('then', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('\\', ThemeAttr('types', 'docker_escape'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('make', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('licenses', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(';', ThemeAttr('types', 'docker_punctuation'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('\\', ThemeAttr('types', 'docker_escape'), False)],
                [ThemeStr('fi', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('&&', ThemeAttr('types', 'docker_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('\\', ThemeAttr('types', 'docker_escape'), False)],
                [ThemeStr('cp', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('-r', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('licenses', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('/install_root/', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('&&', ThemeAttr('types', 'docker_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('\\', ThemeAttr('types', 'docker_escape'), False)],
                [ThemeStr('cp', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('bin/*', ThemeAttr('types', 'docker_string'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('/install_root', ThemeAttr('types', 'docker_string'), False)],
                [ThemeStr('LABEL', ThemeAttr('types', 'docker_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('description', ThemeAttr('types', 'docker_variable'), False),
                 ThemeStr('=', ThemeAttr('types', 'docker_operator'), False),
                 ThemeStr("'A Dockerfile example'", ThemeAttr('types', 'docker_value'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_fluentbit(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_fluentbit

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (["@INCLUDE somefile.conf",
              "[SERVICE]",
              "Flush     5",
              "Daemon    off",
              "Log_Level debug",
              "",
              "[INPUT]",
              "Name  cpu",
              "     Tag   my_cpu",
              "",
              "     [OUTPUT]",
              "     Name  stdout",
              "     Match my*cpu"],
             {},
             [
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('@INCLUDE', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr(' ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('somefile.conf', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('[SERVICE]', ThemeAttr('types', 'ini_section'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Flush', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('     ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('5', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Daemon', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('    ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('off', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Log_Level', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr(' ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('debug', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('[INPUT]', ThemeAttr('types', 'ini_section'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Name', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('  ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('cpu', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('     ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Tag', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('   ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('my_cpu', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('     [OUTPUT]', ThemeAttr('types', 'ini_section'), False)],
                [ThemeStr('     ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Name', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('  ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('stdout', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('     ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Match', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr(' ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('my*cpu', ThemeAttr('types', 'ini_value'), False)]],
             None),
            (["@INCLUDE somefile.conf",
              "[SERVICE]",
              "Flush     5",
              "Daemon    off",
              "Log_Level debug",
              "",
              "[INPUT]",
              "Name  cpu",
              "     Tag   my_cpu",
              "",
              "     [OUTPUT]",
              "     Name  stdout",
              "     Match my*cpu"],
             {"raw": True},
             [
                [ThemeStr('@INCLUDE somefile.conf', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('[SERVICE]', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('Flush     5', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('Daemon    off', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('Log_Level debug', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('[INPUT]', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('Name  cpu', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('     Tag   my_cpu', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('     [OUTPUT]', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('     Name  stdout', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('     Match my*cpu', ThemeAttr('types', 'generic'), False)]],
             None),
            ("# A comment\n"
             "@INCLUDE somefile.conf\n"
             "[SERVICE]\n"
             "Flush     5\n"
             "Daemon    off\n"
             "Log_Level debug\n"
             "\n"
             "[INPUT]\n"
             "Name  cpu\n"
             "     Tag   my_cpu\n"
             "\n"
             "     [OUTPUT]\n"
             "     Name  stdout\n"
             "     Match my*cpu\n",
             {},
             [
                [ThemeStr('# A comment', ThemeAttr('types', 'ini_comment'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('@INCLUDE', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr(' ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('somefile.conf', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('[SERVICE]', ThemeAttr('types', 'ini_section'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Flush', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('     ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('5', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Daemon', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('    ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('off', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Log_Level', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr(' ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('debug', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('[INPUT]', ThemeAttr('types', 'ini_section'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Name', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('  ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('cpu', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('     ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Tag', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('   ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('my_cpu', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('     [OUTPUT]', ThemeAttr('types', 'ini_section'), False)],
                [ThemeStr('     ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Name', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr('  ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('stdout', ThemeAttr('types', 'ini_value'), False)],
                [ThemeStr('     ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('Match', ThemeAttr('types', 'ini_key'), False),
                 ThemeStr(' ', ThemeAttr('types', 'ini_separator'), False),
                 ThemeStr('my*cpu', ThemeAttr('types', 'ini_value'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_haproxy(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_haproxy

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (["global",
              "    log /dev/log local0",
              "    log /dev/log local1 notice",
              "defaults",
              "    timeout server  50s",
              "frontend http_front",
              "    bind *:80",
              "    server app1 10.0.0.10:8080 check"],
             {},
             [
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('global', ThemeAttr('types', 'haproxy_section'), False),
                 ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('', ThemeAttr('types', 'haproxy_label'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('log', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('/dev/log local0', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('log', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('/dev/log local1 notice', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('defaults', ThemeAttr('types', 'haproxy_section'), False),
                 ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('', ThemeAttr('types', 'haproxy_label'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('timeout', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('server  50s', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('frontend', ThemeAttr('types', 'haproxy_section'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('http_front', ThemeAttr('types', 'haproxy_label'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('bind', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('*:80', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('server', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('app1 10.0.0.10:8080 check', ThemeAttr('types', 'generic'), False)]],
             None),
            ("global\n"
             "    log /dev/log local0\n"
             "    log /dev/log local1 notice\n"
             "defaults\n"
             "    timeout server  50s\n"
             "frontend http_front\n"
             "    bind *:80\n"
             "    server app1 10.0.0.10:8080 check",
             {},
             [
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('global', ThemeAttr('types', 'haproxy_section'), False),
                 ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('', ThemeAttr('types', 'haproxy_label'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('log', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('/dev/log local0', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('log', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('/dev/log local1 notice', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('defaults', ThemeAttr('types', 'haproxy_section'), False),
                 ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('', ThemeAttr('types', 'haproxy_label'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('timeout', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('server  50s', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False),
                 ThemeStr('frontend', ThemeAttr('types', 'haproxy_section'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('http_front', ThemeAttr('types', 'haproxy_label'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('bind', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('*:80', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('server', ThemeAttr('types', 'haproxy_setting'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('app1 10.0.0.10:8080 check', ThemeAttr('types', 'generic'), False)]],
             None),
            ("global\n"
             "    log /dev/log local0\n"
             "    log /dev/log local1 notice\n"
             "defaults\n"
             "    timeout server  50s\n"
             "frontend http_front\n"
             "    bind *:80\n"
             "    server app1 10.0.0.10:8080 check",
             {"raw": True},
             [
                [ThemeStr('global', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    log /dev/log local0', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    log /dev/log local1 notice', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('defaults', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    timeout server  50s', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('frontend http_front', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    bind *:80', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    server app1 10.0.0.10:8080 check',
                          ThemeAttr('types', 'generic'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_html(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_html

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # pylint: disable-next=line-length
            (["<!-- A comment -->",
              "<!DOCTYPE html>",
              "<html>",
              "<body>",
              "<h1>My First Heading</h1>",
              "<img src='w3schools.jpg' alt='W3Schools.com' width='104' height='142'>",
              "   <p>My first paragraph.</p>",
              "   </body>",
              "   </html>"],
             {},
             [
                [ThemeStr('<!-- A comment -->', ThemeAttr('types', 'xml_comment'), False)],
                [ThemeStr('<!DOCTYPE html>',
                 ThemeAttr('types', 'html_comment_preprocessor'), False)],
                [ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('html', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False)],
                [ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('body', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False)],
                [ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('h1', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('My First Heading', ThemeAttr('types', 'generic'), False),
                 ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('/', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('h1', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False)],
                [ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('img', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('src', ThemeAttr('types', 'html_attribute'), False),
                 ThemeStr('=', ThemeAttr('types', 'html_operator'), False),
                 ThemeStr("'w3schools.jpg'", ThemeAttr('types', 'html_value'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('alt', ThemeAttr('types', 'html_attribute'), False),
                 ThemeStr('=', ThemeAttr('types', 'html_operator'), False),
                 ThemeStr("'W3Schools.com'", ThemeAttr('types', 'html_value'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('width', ThemeAttr('types', 'html_attribute'), False),
                 ThemeStr('=', ThemeAttr('types', 'html_operator'), False),
                 ThemeStr("'104'", ThemeAttr('types', 'html_value'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('height', ThemeAttr('types', 'html_attribute'), False),
                 ThemeStr('=', ThemeAttr('types', 'html_operator'), False),
                 ThemeStr("'142'", ThemeAttr('types', 'html_value'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False)],
                [ThemeStr('   ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('p', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('My first paragraph.', ThemeAttr('types', 'generic'), False),
                 ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('/', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('p', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False)],
                [ThemeStr('   ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('/', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('body', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False)],
                [ThemeStr('   ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('<', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('/', ThemeAttr('types', 'html_punctuation'), False),
                 ThemeStr('html', ThemeAttr('types', 'html_tag'), False),
                 ThemeStr('>', ThemeAttr('types', 'html_punctuation'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_ini(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_ini

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("# comment\n"
             "[main]\n"
             "setting1 = foo\n"
             "setting2 = bar", {},
             [
                 [ThemeStr("# comment", ThemeAttr("types", "ini_comment"))],
                 [ThemeStr("[main]", ThemeAttr("types", "ini_section"))],
                 [ThemeStr("setting1", ThemeAttr("types", "ini_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "ini_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("foo", ThemeAttr("types", "ini_value"))],
                 [ThemeStr("setting2", ThemeAttr("types", "ini_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "ini_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("bar", ThemeAttr("types", "ini_value"))]],
             None),
            (["# comment",
              "[main]",
              "  setting1 = foo",
              "  setting2 = bar"], {},
              [
                  [ThemeStr("# comment", ThemeAttr("types", "ini_comment"))],
                  [ThemeStr("[main]", ThemeAttr("types", "ini_section"))],
                  [ThemeStr("  ", ThemeAttr("types", "generic")),
                   ThemeStr("setting1", ThemeAttr("types", "ini_key")),
                   ThemeStr(" ", ThemeAttr("types", "generic")),
                   ThemeStr("=", ThemeAttr("types", "ini_separator")),
                   ThemeStr(" ", ThemeAttr("types", "generic")),
                   ThemeStr("foo", ThemeAttr("types", "ini_value"))],
                  [ThemeStr("  ", ThemeAttr("types", "generic")),
                   ThemeStr("setting2", ThemeAttr("types", "ini_key")),
                   ThemeStr(" ", ThemeAttr("types", "generic")),
                   ThemeStr("=", ThemeAttr("types", "ini_separator")),
                   ThemeStr(" ", ThemeAttr("types", "generic")),
                   ThemeStr("bar", ThemeAttr("types", "ini_value"))]],
             None),
            (["# comment",
              "[main]",
              "setting1 = foo",
              "setting2 = bar"], {"raw": True},
              [
                  [ThemeStr("# comment", ThemeAttr("types", "generic"))],
                  [ThemeStr("[main]", ThemeAttr("types", "generic"))],
                  [ThemeStr("setting1 = foo", ThemeAttr("types", "generic"))],
                  [ThemeStr("setting2 = bar", ThemeAttr("types", "generic"))]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_javascript(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_javascript

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (["// A comment",
              "console.log('log message');",
              "let value1 = 'foo';"],
             {},
              [
                [ThemeStr('// A comment', ThemeAttr('types', 'javascript_comment'), False)],
                [ThemeStr('console', ThemeAttr('types', 'generic'), False),
                 ThemeStr('.', ThemeAttr('types', 'javascript_punctuation'), False),
                 ThemeStr('log', ThemeAttr('types', 'generic'), False),
                 ThemeStr('(', ThemeAttr('types', 'javascript_punctuation'), False),
                 ThemeStr("'log message'", ThemeAttr('types', 'javascript_value'), False),
                 ThemeStr(')', ThemeAttr('types', 'javascript_punctuation'), False),
                 ThemeStr(';', ThemeAttr('types', 'javascript_punctuation'), False)],
                [ThemeStr('let', ThemeAttr('types', 'javascript_builtin'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('value1', ThemeAttr('types', 'generic'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('=', ThemeAttr('types', 'javascript_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr("'foo'", ThemeAttr('types', 'javascript_value'), False),
                 ThemeStr(';', ThemeAttr('types', 'javascript_punctuation'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_key_value(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_key_value

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (["driver:",
              "  string: xe",
              "family:",
              "  string: Arc Pro B-Series",
              "health:",
              "  string: Healthy",
              "model:",
              "  string: B50",
              "pciAddress:",
              "  string: '0000:03:00.0'",
              "pciId:",
              "  string: '0xe212'",
              "pciRoot:",
              "  string: '00'",
              "resource.kubernetes.io/pciBusID:",
              "  string: '0000:03:00.0'",
              "resource.kubernetes.io/pcieRoot:",
              "  string: pci0000:00",
              "sriov:",
              "  bool: true",
              "type:",
              "  string: gpu"],
             {
                "typed": True,
                "sort": True,
                "override_types": {
                    "pciAddress": "hex",
                    "pciId": "hex",
                    "pciRoot": "hex",
                },
                "value_mappings": {
                    "health": {
                        "Healthy": {
                            "context": "main",
                            "type": "status_ok"
                        },
                        "Unhealthy": {
                            "context": "main",
                            "type": "status_not_ok"
                        }
                    }
                },
                "separator": {
                  "type": "id_prefix"
                }
             },
             [
                [ThemeStr('driver', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('xe', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('family', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('Arc Pro B-Series', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('health', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('Healthy', ThemeAttr('main', 'status_ok'), False)],
                [ThemeStr('model', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('B50', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('pciAddress', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('0000', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('03', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('00', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('.', ThemeAttr('types', 'unit'), False),
                 ThemeStr('0', ThemeAttr('types', 'numerical'), False)],
                [ThemeStr('pciId', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('0', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('x', ThemeAttr('types', 'unit'), False),
                 ThemeStr('e212', ThemeAttr('types', 'numerical'), False)],
                [ThemeStr('pciRoot', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('00', ThemeAttr('types', 'numerical'), False)],
                [ThemeStr('resource.kubernetes.io/pciBusID', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('0000:03:00.0', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('resource.kubernetes.io/pcieRoot', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('pci0000:00', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('sriov', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('True', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('type', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('gpu', ThemeAttr('types', 'generic'), False)]],
             None),
            ("driver:\n"
             "  string: xe\n"
             "family:\n"
             "  string: Arc Pro B-Series\n"
             "health:\n"
             "  string: Healthy\n"
             "model:\n"
             "  string: B50\n"
             "pciAddress:\n"
             "  string: '0000:03:00.0'\n"
             "pciId:\n"
             "  string: '0xe212'\n"
             "pciRoot:\n"
             "  string: '00'\n"
             "resource.kubernetes.io/pciBusID:\n"
             "  string: '0000:03:00.0'\n"
             "resource.kubernetes.io/pcieRoot:\n"
             "  string: pci0000:00\n"
             "sriov:\n"
             "  bool: true\n"
             "type:\n"
             "  string: gpu",
             {
                "typed": True,
                "sort": True,
                "override_types": {
                    "pciAddress": "hex",
                    "pciId": "hex",
                    "pciRoot": "hex",
                },
                "value_mappings": {
                    "health": {
                        "Healthy": {
                            "context": "main",
                            "type": "status_ok"
                        },
                        "Unhealthy": {
                            "context": "main",
                            "type": "status_not_ok"
                        }
                    }
                },
                "separator": {
                  "type": "id_prefix"
                }
             },
             [
                [ThemeStr('driver', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('xe', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('family', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('Arc Pro B-Series', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('health', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('Healthy', ThemeAttr('main', 'status_ok'), False)],
                [ThemeStr('model', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('B50', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('pciAddress', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('0000', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('03', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('00', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('.', ThemeAttr('types', 'unit'), False),
                 ThemeStr('0', ThemeAttr('types', 'numerical'), False)],
                [ThemeStr('pciId', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('0', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('x', ThemeAttr('types', 'unit'), False),
                 ThemeStr('e212', ThemeAttr('types', 'numerical'), False)],
                [ThemeStr('pciRoot', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('00', ThemeAttr('types', 'numerical'), False)],
                [ThemeStr('resource.kubernetes.io/pciBusID', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('0000:03:00.0', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('resource.kubernetes.io/pcieRoot', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('pci0000:00', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('sriov', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('True', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('type', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('gpu', ThemeAttr('types', 'generic'), False)]],
             None),
            ({
                "family": {
                    "string": "Arc Pro B-Series",
                },
                "driver": {
                    "string": "xe",
                }
             },
             {
                "typed": True,
                "sort": False,
                "separator": {
                  "type": "id_prefix"
                }
             },
             [
                [ThemeStr('family', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('Arc Pro B-Series', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('driver', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('xe', ThemeAttr('types', 'generic'), False)]],
             None),
            ({
                "family": {
                    "string": "Arc Pro B-Series",
                },
                "driver": {
                    "string": "xe",
                }
             },
             {
                "typed": True,
                "sort": True,
                "separator": {
                  "type": "id_prefix"
                }
             },
             [
                [ThemeStr('driver', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('xe', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('family', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('Arc Pro B-Series', ThemeAttr('types', 'generic'), False)]],
             None),
            ({
                "age": {
                    "age": 12,
                },
                "bool": {
                    "bool": True,
                },
                "boolean": {
                    "boolean": False,
                },
                "size": {
                    "int": "400k",
                },
                "timestamp": {
                    "timestamp": datetime(2023, 5, 6, 16, 2, 39, 12047),
                },
             },
             {
                "typed": True,
                "sort": True,
                "separator": {
                  "type": "id_prefix"
                }
             },
             [
                [ThemeStr('age', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('12', ThemeAttr('types', 'age'), False)],
                [ThemeStr('bool', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('True', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('boolean', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('False', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('size', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('400', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('k', ThemeAttr('types', 'unit'), False)],
                [ThemeStr('timestamp', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('2023', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('-', ThemeAttr('types', 'unit'), False),
                 ThemeStr('05', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('-', ThemeAttr('types', 'unit'), False),
                 ThemeStr('06', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(' ', ThemeAttr('types', 'unit'), False),
                 ThemeStr('16', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('02', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('39', ThemeAttr('types', 'numerical'), False)]],
             None),
            ({
                "family": "Arc Pro B-Series",
                "driver": "xe",
             },
             {
                "typed": False,
                "sort": True,
                "separator": {
                  "type": "id_prefix"
                }
             },
             [
                [ThemeStr('driver', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('xe', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('family', ThemeAttr('types', 'key'), False),
                 ThemeRef('separators', 'id_prefix', False),
                 ThemeStr('Arc Pro B-Series', ThemeAttr('types', 'generic'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            if isinstance(indata_quoted, str):
                indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_known_hosts(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_known_hosts

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # comment, empty line, ed25519 key, IP-address
            ("# comment\n\n"
             "127.0.0.1 ssh-ed25519 AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa\n",
             {},
             [
                 [ThemeStr("# comment", ThemeAttr("types", "known_hosts_comment"))],
                 [],
                 [ThemeStr("127.0.0.1", ThemeAttr("types", "known_hosts_hostname")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("ssh-ed25519", ThemeAttr("types", "known_hosts_crypto")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa",
                           ThemeAttr("types", "known_hosts_key"))]],
             None),
            # comment, ed25519 key, IP-address, raw
            ("# comment\n"
             "127.0.0.1 ssh-ed25519 AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa\n",
             {"raw": True},
             [
                 [ThemeStr("# comment", ThemeAttr("types", "generic"))],
                 [ThemeStr("127.0.0.1 ssh-ed25519 AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa",
                           ThemeAttr("types", "generic"))]],
             None),
            # comment, ecdsa key, localhost, list of lines
            (["# comment",
              "localhost ecdsa-sha2-nistp256 AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa"],
             {},
             [
                 [ThemeStr("# comment", ThemeAttr("types", "known_hosts_comment"))],
                 [ThemeStr("localhost", ThemeAttr("types", "known_hosts_hostname")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("ecdsa-sha2-nistp256", ThemeAttr("types", "known_hosts_crypto")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa",
                           ThemeAttr("types", "known_hosts_key"))]],
             None),
            # rsa key, hashed hostname
            ("|1|u+cnAJeulQDtZuXXyxfq3LKri54=|EkYTz93M1pdd4ncvtvdEAXYImV8= "
             "ssh-rsa AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa\n",
             {},
             [
                 [ThemeStr("|1|u+cnAJeulQDtZuXXyxfq3LKri54=|EkYTz93M1pdd4ncvtvdEAXYImV8=",
                           ThemeAttr("types", "known_hosts_hostname")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("ssh-rsa", ThemeAttr("types", "known_hosts_crypto")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa",
                           ThemeAttr("types", "known_hosts_key"))]],
             None),
            # keyring
            ("mvs* zos-key-ring-label=\"KeyRingOwner/SSHKnownHostsRing mvs1-ssh-rsa\"",
             {},
             [
                 [ThemeStr("mvs*", ThemeAttr("types", "known_hosts_hostname")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("zos-key-ring-label=", ThemeAttr("types", "known_hosts_crypto")),
                  ThemeStr("\"KeyRingOwner/SSHKnownHostsRing mvs1-ssh-rsa\"",
                           ThemeAttr("types", "known_hosts_key"))]],
             None),
            # revoked key, ed25519 key, IP-address
            ("@revoked 127.0.0.1 ssh-ed25519 AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa\n",
             {},
             [
                 [ThemeStr("@revoked", ThemeAttr("types", "known_hosts_revoked")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("127.0.0.1", ThemeAttr("types", "known_hosts_hostname")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("ssh-ed25519", ThemeAttr("types", "known_hosts_crypto")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa",
                           ThemeAttr("types", "known_hosts_key"))]],
             None),
            # certificate authority, ed25519 key, IP-address
            ("@cert-authority 127.0.0.1 ssh-ed25519 AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa\n",
             {},
             [
                 [ThemeStr("@cert-authority", ThemeAttr("types", "known_hosts_cert_authority")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("127.0.0.1", ThemeAttr("types", "known_hosts_hostname")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("ssh-ed25519", ThemeAttr("types", "known_hosts_crypto")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("AAAAfdshaklfdsahfjksldafhsadk4532423fsadfdsa",
                           ThemeAttr("types", "known_hosts_key"))]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_mosquitto(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_mosquitto

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("# comment\n"
             "description testcase\n"
             "author \"Test Testson\"\n"
             "respawn\n"
             "per_listener_settings false\n"
             "listener 1883\n"
             "global_max_connections -1\n"
             "start on net-device-up\n"
             "persistent_client_expiration 2d\n"
             "accept_protocol_versions 3, 4\n"
             "accept_protocol_versions 3,4,5\n"
             "listener 0 /tmp/mosquitto.sock\n"
             "pattern write sensor/%u/data\n"
             "bridge_tcp_keepalive 0 1 42\n"
             "",
             {},
             [
                 [ThemeStr("# comment", ThemeAttr("types", "mosquitto_comment"))],
                 [ThemeStr("description", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("testcase", ThemeAttr("types", "mosquitto_value"))],
                 [ThemeStr("author", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("\"Test Testson\"", ThemeAttr("types", "mosquitto_value"))],
                 [ThemeStr("respawn", ThemeAttr("types", "mosquitto_keyword"))],
                 [ThemeStr("per_listener_settings", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("false", ThemeAttr("types", "mosquitto_number"))],
                 [ThemeStr("listener", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("1883", ThemeAttr("types", "mosquitto_number"))],
                 [ThemeStr("global_max_connections", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("-1", ThemeAttr("types", "mosquitto_number"))],
                 [ThemeStr("start on", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("net-device-up", ThemeAttr("types", "mosquitto_value"))],
                 [ThemeStr("persistent_client_expiration", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("2", ThemeAttr("types", "generic")),
                  ThemeStr("d", ThemeAttr("types", "mosquitto_unit"))],
                 [ThemeStr("accept_protocol_versions", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("3", ThemeAttr("types", "mosquitto_number")),
                  ThemeStr(", 4", ThemeAttr("types", "mosquitto_number"))],
                 [ThemeStr("accept_protocol_versions", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("3", ThemeAttr("types", "mosquitto_number")),
                  ThemeStr(",4,5", ThemeAttr("types", "mosquitto_number"))],
                 [ThemeStr("listener", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("0", ThemeAttr("types", "mosquitto_number")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("/tmp/mosquitto.sock", ThemeAttr("types", "mosquitto_value"))],
                 [ThemeStr("pattern", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("write", ThemeAttr("types", "mosquitto_unit")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("sensor/%u/data", ThemeAttr("types", "mosquitto_value"))],
                 [ThemeStr("bridge_tcp_keepalive", ThemeAttr("types", "mosquitto_keyword")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("0", ThemeAttr("types", "mosquitto_number")),
                  ThemeStr(" 1 42", ThemeAttr("types", "mosquitto_number"))],
             ],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_nginx(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_nginx

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("worker_processes auto;\n"
             "events {\n"
             "    worker_connections 1024;\n"
             "}\n"
             "\n"
             "if ($request_filename ~ "
             ".*\\.(?:js|css|jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm)$) {\n"
             "  expires 90d;\n"
             "}\n"
             "\n"
             "rewrite ^/k8s/clusters/.*/proxy(.*) /$1 break;\n",
             {},
             [
                 [ThemeStr("worker_processes", ThemeAttr("types", "nginx_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("auto", ThemeAttr("types", "nginx_value")),
                  ThemeStr(";", ThemeAttr("types", "nginx_punctuation"))],
                 [ThemeStr("events", ThemeAttr("types", "nginx_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("{", ThemeAttr("types", "nginx_punctuation"))],
                 [ThemeStr("    ", ThemeAttr("types", "generic")),
                  ThemeStr("worker_connections", ThemeAttr("types", "nginx_namespace")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("1024", ThemeAttr("types", "nginx_value")),
                  ThemeStr(";", ThemeAttr("types", "nginx_punctuation"))],
                 [ThemeStr("}", ThemeAttr("types", "nginx_punctuation"))],
                 [],
                 [ThemeStr("if", ThemeAttr("types", "nginx_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("(", ThemeAttr("types", "nginx_value")),
                  ThemeStr("$request_filename", ThemeAttr("types", "nginx_variable")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("~", ThemeAttr("types", "nginx_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr(".*\\.(?:js|css|jpg|jpeg|gif|png|ico|cur|gz|svg|"
                           "svgz|mp4|ogg|ogv|webm)$)", ThemeAttr("types", "nginx_regex")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("{", ThemeAttr("types", "nginx_punctuation"))],
                 [ThemeStr("  ", ThemeAttr("types", "generic")),
                  ThemeStr("expires", ThemeAttr("types", "nginx_namespace")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("90d", ThemeAttr("types", "nginx_value")),
                  ThemeStr(";", ThemeAttr("types", "nginx_punctuation"))],
                 [ThemeStr("}", ThemeAttr("types", "nginx_punctuation"))],
                 [],
                 [ThemeStr("rewrite", ThemeAttr("types", "nginx_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("^/k8s/clusters/.*/proxy(.*)", ThemeAttr("types", "nginx_value")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("/", ThemeAttr("types", "nginx_value")),
                  ThemeStr("$1", ThemeAttr("types", "nginx_variable")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("break", ThemeAttr("types", "nginx_value")),
                  ThemeStr(";", ThemeAttr("types", "nginx_punctuation"))]],
                None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_promql(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_promql

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (["(",
              "  sum by(gateway_class_type) (",
              "    label_replace(",
              "      (",
              "        kube_customresource_gateway_info{programmed='True'}",
              # pylint: disable-next=comparison-with-callable
              "        and on(gateway_class) kube_customresource_gateway_class_info{accepted='True', controller='openshift.io/gateway-controller/v1'}",  # noqa: E501
              "      ),",
              "      'gateway_class_type', 'openshift', '', ''",
              "    )",
              "  )",
              ")"],
             {},
             [
                [ThemeStr('(', ThemeAttr('types', 'promql_operator'), False)],
                [ThemeStr('  ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('sum', ThemeAttr('types', 'promql_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('by', ThemeAttr('types', 'promql_keyword'), False),
                 ThemeStr('(', ThemeAttr('types', 'promql_operator'), False),
                 ThemeStr('gateway_class_type', ThemeAttr('types', 'promql_variable'), False),
                 ThemeStr(')', ThemeAttr('types', 'promql_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('(', ThemeAttr('types', 'promql_operator'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('label_replace', ThemeAttr('types', 'promql_builtin'), False),
                 ThemeStr('(', ThemeAttr('types', 'promql_operator'), False)],
                [ThemeStr('      ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('(', ThemeAttr('types', 'promql_operator'), False)],
                [ThemeStr('        ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('kube_customresource_gateway_info',
                          ThemeAttr('types', 'promql_variable'), False),
                 ThemeStr('{', ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('programmed', ThemeAttr('types', 'promql_label'), False),
                 ThemeStr('=', ThemeAttr('types', 'promql_operator'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('True', ThemeAttr('types', 'promql_string'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('}', ThemeAttr('types', 'promql_punctuation'), False)],
                [ThemeStr('        ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('and', ThemeAttr('types', 'promql_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('on', ThemeAttr('types', 'promql_keyword'), False),
                 ThemeStr('(', ThemeAttr('types', 'promql_operator'), False),
                 ThemeStr('gateway_class', ThemeAttr('types', 'promql_variable'), False),
                 ThemeStr(')', ThemeAttr('types', 'promql_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('kube_customresource_gateway_class_info',
                          ThemeAttr('types', 'promql_variable'), False),
                 ThemeStr('{', ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('accepted', ThemeAttr('types', 'promql_label'), False),
                 ThemeStr('=', ThemeAttr('types', 'promql_operator'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('True', ThemeAttr('types', 'promql_string'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr(',', ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('controller', ThemeAttr('types', 'promql_label'), False),
                 ThemeStr('=', ThemeAttr('types', 'promql_operator'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('openshift.io/gateway-controller/v1',
                          ThemeAttr('types', 'promql_string'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('}', ThemeAttr('types', 'promql_punctuation'), False)],
                [ThemeStr('      ', ThemeAttr('types', 'generic'), False),
                 ThemeStr(')', ThemeAttr('types', 'promql_operator'), False),
                 ThemeStr(',', ThemeAttr('types', 'promql_punctuation'), False)],
                [ThemeStr('      ', ThemeAttr('types', 'generic'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('gateway_class_type', ThemeAttr('types', 'promql_string'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr(',', ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr('openshift', ThemeAttr('types', 'promql_string'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr(',', ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr(',', ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False),
                 ThemeStr("'", ThemeAttr('types', 'promql_punctuation'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'generic'), False),
                 ThemeStr(')', ThemeAttr('types', 'promql_operator'), False)],
                [ThemeStr('  ', ThemeAttr('types', 'generic'), False),
                 ThemeStr(')', ThemeAttr('types', 'promql_operator'), False)],
                [ThemeStr(')', ThemeAttr('types', 'promql_operator'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_python(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_python

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (["#! /usr/bin/env python3",
              "",
              "def main() -> None:",
              "    print('hello world')",
              "",
              "if __name__ == '__main__':",
              "    main()"],
             {},
             [
                [ThemeStr('#! /usr/bin/env python3', ThemeAttr('types', 'python_comment'), False)],
                [],
                [ThemeStr('def', ThemeAttr('types', 'python_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False),
                 ThemeStr('main', ThemeAttr('types', 'python_function'), False),
                 ThemeStr('(', ThemeAttr('types', 'python_punctuation'), False),
                 ThemeStr(')', ThemeAttr('types', 'python_punctuation'), False),
                 ThemeStr(' ', ThemeAttr('types', 'python_text'), False),
                 ThemeStr('-', ThemeAttr('types', 'python_operator'), False),
                 ThemeStr('>', ThemeAttr('types', 'python_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'python_text'), False),
                 ThemeStr('None', ThemeAttr('types', 'python_builtin'), False),
                 ThemeStr(':', ThemeAttr('types', 'python_punctuation'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'python_text'), False),
                 ThemeStr('print', ThemeAttr('types', 'python_builtin'), False),
                 ThemeStr('(', ThemeAttr('types', 'python_punctuation'), False),
                 ThemeStr("'", ThemeAttr('types', 'python_value'), False),
                 ThemeStr('hello world', ThemeAttr('types', 'python_value'), False),
                 ThemeStr("'", ThemeAttr('types', 'python_value'), False),
                 ThemeStr(')', ThemeAttr('types', 'python_punctuation'), False)],
                [],
                [ThemeStr('if', ThemeAttr('types', 'python_keyword'), False),
                 ThemeStr(' ', ThemeAttr('types', 'python_text'), False),
                 ThemeStr('__name__', ThemeAttr('types', 'python_variable'), False),
                 ThemeStr(' ', ThemeAttr('types', 'python_text'), False),
                 ThemeStr('==', ThemeAttr('types', 'python_operator'), False),
                 ThemeStr(' ', ThemeAttr('types', 'python_text'), False),
                 ThemeStr("'", ThemeAttr('types', 'python_value'), False),
                 ThemeStr('__main__', ThemeAttr('types', 'python_value'), False),
                 ThemeStr("'", ThemeAttr('types', 'python_value'), False),
                 ThemeStr(':', ThemeAttr('types', 'python_punctuation'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'python_text'), False),
                 ThemeStr('main', ThemeAttr('types', 'python_name'), False),
                 ThemeStr('(', ThemeAttr('types', 'python_punctuation'), False),
                 ThemeStr(')', ThemeAttr('types', 'python_punctuation'), False)]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_xml(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_xml

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<h:table xmlns:h=\"http://www.w3.org/TR/html4/\">\n"
                "<h:tr>\n"
                "<h:td>Apples</h:td>\n"
                "</h:tr>\n"
                "</h:table>\n"
                "",
                {},
                [
                    [ThemeStr("<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                              ThemeAttr("types", "xml_comment_preprocessor"))],
                    [ThemeStr("<h:table", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("xmlns:h=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"http://www.w3.org/TR/html4/\"",
                              ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("<h:tr", ThemeAttr("types", "xml_tag")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("<h:td", ThemeAttr("types", "xml_tag")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag")),
                     ThemeStr("Apples",
                              ThemeAttr("types", "generic")),
                     ThemeStr("</h:td>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("</h:tr>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("</h:table>", ThemeAttr("types", "xml_tag"))],
                ], None),
            (
                [
                    "<html xsl:version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">",
                    "<body style=\"font-family:Arial;font-size:12pt;background-color:#EEEEEE\">",
                    "<xsl:for-each select=\"breakfast_menu/food\">",
                    "  <div style=\"background-color:teal;color:white;padding:4px\">",
                    "    <span style=\"font-weight:bold\"><xsl:value-of select=\"name\"/>"
                    " - </span>",
                    "    <xsl:value-of select=\"price\"/>",
                    "  </div>",
                    "  <div style=\"margin-left:20px;margin-bottom:1em;font-size:10pt\">",
                    "    <p>",
                    "      <xsl:value-of select=\"description\"/>",
                    "      <span style=\"font-style:italic\"> "
                    "(<xsl:value-of select=\"calories\"/> calories per serving)</span>",
                    "    </p>",
                    "  </div>",
                    "</xsl:for-each>",
                ],
                {},
                [
                    [ThemeStr("<html", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("xsl:version=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"1.0\"", ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("xmlns:xsl=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"http://www.w3.org/1999/XSL/Transform\"",
                              ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("<body", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("style=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"font-family:Arial;font-size:12pt;background-color:#EEEEEE\"",
                              ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("<xsl:for-each", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("select=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"breakfast_menu/food\"", ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("  ", ThemeAttr("types", "generic")),
                     ThemeStr("<div", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("style=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"background-color:teal;color:white;padding:4px\"",
                              ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("    ", ThemeAttr("types", "generic")),
                     ThemeStr("<span", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("style=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"font-weight:bold\"", ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag")),
                     ThemeStr("<xsl:value-of", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("select=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"name\"", ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr("/>", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("-", ThemeAttr("types", "generic")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("</span>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("    ", ThemeAttr("types", "generic")),
                     ThemeStr("<xsl:value-of", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("select=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"price\"", ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr("/>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("  ", ThemeAttr("types", "generic")),
                     ThemeStr("</div>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("  ", ThemeAttr("types", "generic")),
                     ThemeStr("<div", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("style=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"margin-left:20px;margin-bottom:1em;font-size:10pt\"",
                              ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("    ", ThemeAttr("types", "generic")),
                     ThemeStr("<p", ThemeAttr("types", "xml_tag")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("      ", ThemeAttr("types", "generic")),
                     ThemeStr("<xsl:value-of", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("select=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"description\"", ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr("/>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("      ", ThemeAttr("types", "generic")),
                     ThemeStr("<span", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("style=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"font-style:italic\"", ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr(">", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("(", ThemeAttr("types", "generic")),
                     ThemeStr("<xsl:value-of", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("select=", ThemeAttr("types", "xml_attribute_key")),
                     ThemeStr("\"calories\"", ThemeAttr("types", "xml_attribute_value")),
                     ThemeStr("/>", ThemeAttr("types", "xml_tag")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("calories", ThemeAttr("types", "generic")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("per", ThemeAttr("types", "generic")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("serving)", ThemeAttr("types", "generic")),
                     ThemeStr("</span>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("    ", ThemeAttr("types", "generic")),
                     ThemeStr("</p>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("  ", ThemeAttr("types", "generic")),
                     ThemeStr("</div>", ThemeAttr("types", "xml_tag"))],
                    [ThemeStr("</xsl:for-each>", ThemeAttr("types", "xml_tag"))],
                ], None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_caddyfile(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_caddyfile

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ([".:53 {",
              "    # comment",
              "",
              "}"], {},
             [
                [ThemeStr('.:53', ThemeAttr('types', 'caddyfile_site'), False),
                 ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                 ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                [ThemeStr('    # comment', ThemeAttr('types', 'caddyfile_comment'), False)],
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)]
            ], None),
            ([".:53 {",
              "    errors",
              "    health {",
              "       lameduck 5s",
              "    }",
              "    ready",
              "    kubernetes cluster.local in-addr.arpa ip6.arpa {",
              "       pods insecure",
              "       fallthrough in-addr.arpa ip6.arpa",
              "       ttl 30",
              "    }",
              "    prometheus :9153",
              "    forward . /etc/resolv.conf {",
              "       max_concurrent 1000",
              "    }",
              "    cache 30",
              "    loop",
              "    reload",
              "    loadbalance",
              "}"], {},
             [
                [ThemeStr('.:53', ThemeAttr('types', 'caddyfile_site'), False),
                 ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                 ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('errors', ThemeAttr('types', 'caddyfile_directive'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('health', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                 ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('lameduck', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' 5s', ThemeAttr('types', 'caddyfile_argument'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_block'), False),
                 ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('ready', ThemeAttr('types', 'caddyfile_directive'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('kubernetes', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' cluster.local in-addr.arpa ip6.arpa',
                          ThemeAttr('types', 'caddyfile_argument'), False),
                 ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                 ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('pods', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' insecure', ThemeAttr('types', 'caddyfile_argument'), False)],
                [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('fallthrough', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' in-addr.arpa ip6.arpa',
                          ThemeAttr('types', 'caddyfile_argument'), False)],
                [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('ttl', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' 30', ThemeAttr('types', 'caddyfile_argument'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_block'), False),
                 ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('prometheus', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' :9153', ThemeAttr('types', 'caddyfile_argument'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('forward', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' . /etc/resolv.conf', ThemeAttr('types', 'caddyfile_argument'), False),
                 ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                 ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('max_concurrent', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' 1000', ThemeAttr('types', 'caddyfile_argument'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_block'), False),
                 ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('cache', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr(' 30', ThemeAttr('types', 'caddyfile_argument'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('loop', ThemeAttr('types', 'caddyfile_directive'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('reload', ThemeAttr('types', 'caddyfile_directive'), False)],
                [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                 ThemeStr('loadbalance', ThemeAttr('types', 'caddyfile_directive'), False)],
                [ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)]
            ], None),
            (".:53 {\n"
             "    errors\n"
             "    health {\n"
             "       lameduck 5s\n"
             "    }\n"
             "    ready\n"
             "    kubernetes cluster.local in-addr.arpa ip6.arpa {\n"
             "       pods insecure\n"
             "       fallthrough in-addr.arpa ip6.arpa\n"
             "       ttl 30\n"
             "    }\n"
             "    prometheus :9153\n"
             "    forward . /etc/resolv.conf {\n"
             "       max_concurrent 1000\n"
             "    }\n"
             "    cache 30\n"
             "    loop\n"
             "    reload\n"
             "    loadbalance\n"
             "}", {},
             [
                 [ThemeStr('.:53', ThemeAttr('types', 'caddyfile_site'), False),
                  ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                  ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('errors', ThemeAttr('types', 'caddyfile_directive'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('health', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                  ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                 [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('lameduck', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' 5s', ThemeAttr('types', 'caddyfile_argument'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_block'), False),
                  ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('ready', ThemeAttr('types', 'caddyfile_directive'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('kubernetes', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' cluster.local in-addr.arpa ip6.arpa',
                           ThemeAttr('types', 'caddyfile_argument'), False),
                  ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                  ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                 [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('pods', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' insecure', ThemeAttr('types', 'caddyfile_argument'), False)],
                 [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('fallthrough', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' in-addr.arpa ip6.arpa',
                           ThemeAttr('types', 'caddyfile_argument'), False)],
                 [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('ttl', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' 30', ThemeAttr('types', 'caddyfile_argument'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_block'), False),
                  ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('prometheus', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' :9153', ThemeAttr('types', 'caddyfile_argument'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('forward', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' . /etc/resolv.conf', ThemeAttr('types', 'caddyfile_argument'), False),
                  ThemeStr(' ', ThemeAttr('types', 'caddyfile_block'), False),
                  ThemeStr('{', ThemeAttr('types', 'caddyfile_block'), False)],
                 [ThemeStr('       ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('max_concurrent', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' 1000', ThemeAttr('types', 'caddyfile_argument'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_block'), False),
                  ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('cache', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr(' 30', ThemeAttr('types', 'caddyfile_argument'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('loop', ThemeAttr('types', 'caddyfile_directive'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('reload', ThemeAttr('types', 'caddyfile_directive'), False)],
                 [ThemeStr('    ', ThemeAttr('types', 'caddyfile_directive'), False),
                  ThemeStr('loadbalance', ThemeAttr('types', 'caddyfile_directive'), False)],
                 [ThemeStr('}', ThemeAttr('types', 'caddyfile_block'), False)]], None),
            ([".:53 {",
              "    # comment",
              "}"], {"raw": True},
             [
                [ThemeStr('.:53 {', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('    # comment', ThemeAttr('types', 'generic'), False)],
                [ThemeStr('}', ThemeAttr('types', 'generic'), False)]], None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              "          output:\n" \
                              f"{yaml_dump(tmp, base_indent=17)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__indata__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__indata__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_powershell(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_powershell

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("# Comment\n"
             "$ErrorActionPreference = 'Continue'\n"
             "function CheckFirewallRuleError {\n"
             "    if ($error[0]) {\n"
             "        if (($error[0].Exception.NativeErrorCode) "
             "-and ($error[0].Exception.NativeErrorCode.ToString() -eq \"AlreadyExists\")) {\n"
             "            Write-Host \"Detected Existing Firewall Rule, Nothing To Do\"\n"
             "        } else {\n"
             "            Write-Host \"Error Encountered Setting Up Required Firewall Rule\"\n"
             "            $error[0].Exception\n"
             "            exit 1\n"
             "        }\n"
             "    }\n"
             "}\n",
             {},
             [
                 [ThemeStr("# Comment", ThemeAttr("types", "powershell_comment"), False)],
                 [ThemeStr("$ErrorActionPreference",
                           ThemeAttr("types", "powershell_variable"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("=", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("'Continue'", ThemeAttr("types", "powershell_value"), False)],
                 [ThemeStr("function", ThemeAttr("types", "powershell_keyword"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("CheckFirewallRuleError", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("{", ThemeAttr("types", "powershell_punctuation"), False)],
                 [ThemeStr("    ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("if", ThemeAttr("types", "powershell_keyword"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("(", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("$error", ThemeAttr("types", "powershell_variable"), False),
                  ThemeStr("[", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("0", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr("]", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(")", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("{", ThemeAttr("types", "powershell_punctuation"), False)],
                 [ThemeStr("        ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("if", ThemeAttr("types", "powershell_keyword"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("(", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("(", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("$error", ThemeAttr("types", "powershell_variable"), False),
                  ThemeStr("[", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("0", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr("]", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(".", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("Exception", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr(".", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("NativeErrorCode", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr(")", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("-and", ThemeAttr("types", "powershell_operator"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("(", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("$error", ThemeAttr("types", "powershell_variable"), False),
                  ThemeStr("[", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("0", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr("]", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(".", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("Exception", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr(".", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("NativeErrorCode", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr(".", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("ToString", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr("(", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(")", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("-eq", ThemeAttr("types", "powershell_operator"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("\"", ThemeAttr("types", "powershell_value"), False),
                  ThemeStr("AlreadyExists", ThemeAttr("types", "powershell_value"), False),
                  ThemeStr("\"", ThemeAttr("types", "powershell_value"), False),
                  ThemeStr(")", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(")", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("{", ThemeAttr("types", "powershell_punctuation"), False)],
                 [ThemeStr("            ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("Write-Host", ThemeAttr("types", "powershell_builtin"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("\"", ThemeAttr("types", "powershell_value"), False),
                  ThemeStr("Detected Existing Firewall Rule, Nothing To Do",
                           ThemeAttr("types", "powershell_value"), False),
                  ThemeStr("\"", ThemeAttr("types", "powershell_value"), False)],
                 [ThemeStr("        ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("}", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("else", ThemeAttr("types", "powershell_keyword"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("{", ThemeAttr("types", "powershell_punctuation"), False)],
                 [ThemeStr("            ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("Write-Host", ThemeAttr("types", "powershell_builtin"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("\"", ThemeAttr("types", "powershell_value"), False),
                  ThemeStr("Error Encountered Setting Up Required Firewall Rule",
                           ThemeAttr("types", "powershell_value"), False),
                  ThemeStr("\"", ThemeAttr("types", "powershell_value"), False)],
                 [ThemeStr("            ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("$error", ThemeAttr("types", "powershell_variable"), False),
                  ThemeStr("[", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("0", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr("]", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr(".", ThemeAttr("types", "powershell_punctuation"), False),
                  ThemeStr("Exception", ThemeAttr("types", "powershell_name"), False)],
                 [ThemeStr("            ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("exit", ThemeAttr("types", "powershell_name"), False),
                  ThemeStr(" ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("1", ThemeAttr("types", "powershell_name"), False)],
                 [ThemeStr("        ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("}", ThemeAttr("types", "powershell_punctuation"), False)],
                 [ThemeStr("    ", ThemeAttr("types", "powershell_text"), False),
                  ThemeStr("}", ThemeAttr("types", "powershell_punctuation"), False)],
                 [ThemeStr("}", ThemeAttr("types", "powershell_punctuation"), False)],
             ],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_python_traceback(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_python_traceback

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("Traceback (most recent call last):\n"
             " File \"<stdin>\", line 1, in <module>\n"
             "ZeroDivisionError: division by zero",
             {},
             [
                 [ThemeStr("Traceback (most recent call last):",
                           ThemeAttr("logview", "severity_error"))],
                 [ThemeStr(" File \"<stdin>\", line 1, in <module>",
                  ThemeAttr("logview", "severity_error"))],
                 [ThemeStr("ZeroDivisionError", ThemeAttr("logview", "severity_error")),
                  ThemeStr(": ", ThemeAttr("types", "generic")),
                  ThemeStr("division by zero", ThemeAttr("types", "generic"))]],
             None),
            (["Traceback (most recent call last):",
              " File \"<stdin>\", line 1, in <module>",
              "ZeroDivisionError: division by zero"],
             {},
             [
                 [ThemeStr("Traceback (most recent call last):",
                           ThemeAttr("logview", "severity_error"))],
                 [ThemeStr(" File \"<stdin>\", line 1, in <module>",
                  ThemeAttr("logview", "severity_error"))],
                 [ThemeStr("ZeroDivisionError", ThemeAttr("logview", "severity_error")),
                  ThemeStr(": ", ThemeAttr("types", "generic")),
                  ThemeStr("division by zero", ThemeAttr("types", "generic"))]],
             None),
            (["",
              "Traceback (most recent call last):",
              " File \"<stdin>\", line 1, in <module>",
              "ZeroDivisionError: division by zero"],
             {},
             [
                 [ThemeStr("Traceback (most recent call last):",
                           ThemeAttr("logview", "severity_error"))],
                 [ThemeStr(" File \"<stdin>\", line 1, in <module>",
                  ThemeAttr("logview", "severity_error"))],
                 [ThemeStr("ZeroDivisionError", ThemeAttr("logview", "severity_error")),
                  ThemeStr(": ", ThemeAttr("types", "generic")),
                  ThemeStr("division by zero", ThemeAttr("types", "generic"))]],
             None),
            (["",
              "Traceback (most recent call last):",
              " File \"<stdin>\", line 1, in <module>",
              "ZeroDivisionError: division by zero"],
             {"raw": True},
             [
                 [ThemeStr("", ThemeAttr("types", "generic"))],
                 [ThemeStr("Traceback (most recent call last):",
                           ThemeAttr("types", "generic"))],
                 [ThemeStr(" File \"<stdin>\", line 1, in <module>",
                  ThemeAttr("types", "generic"))],
                 [ThemeStr("ZeroDivisionError: division by zero", ThemeAttr("types", "generic"))]],
             None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_toml(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_toml

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (
                ["# comment",
                 "title = \"TOML Example\"",
                 "",
                 "[owner]",
                 "dob = 1979-05-27T07:32:00-08:00",
                 "",
                 "[database]",
                 "enabled = true",
                 "ports = [ 8000, 8001, 8002 ]",
                 "data = [ [\"delta\", \"phi\"], [3.14] ]",
                 "temp_targets = { cpu = 79.5, case = 72.0 }",
                 "",
                 "[servers]",
                 "",
                 "[servers.alpha]"],
                {},
                [[ThemeStr("# comment", ThemeAttr("types", "toml_comment"))],
                 [ThemeStr("title", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value")),
                  ThemeStr("TOML Example", ThemeAttr("types", "toml_value")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value"))],
                 [],
                 [ThemeStr("[", ThemeAttr("types", "toml_section")),
                  ThemeStr("owner", ThemeAttr("types", "toml_section")),
                  ThemeStr("]", ThemeAttr("types", "toml_section"))],
                 [ThemeStr("dob", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("1979-05-27T07:32:00-08:00", ThemeAttr("types", "toml_value")),
                  ],
                 [],
                 [ThemeStr("[", ThemeAttr("types", "toml_section")),
                  ThemeStr("database", ThemeAttr("types", "toml_section")),
                  ThemeStr("]", ThemeAttr("types", "toml_section"))],
                 [ThemeStr("enabled", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("true", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("ports", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("[", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("8000", ThemeAttr("types", "toml_value")),
                  ThemeStr(",", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("8001", ThemeAttr("types", "toml_value")),
                  ThemeStr(",", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("8002", ThemeAttr("types", "toml_value")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("]", ThemeAttr("types", "toml_punctuation"))],
                 [ThemeStr("data", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("[", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("[", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value")),
                  ThemeStr("delta", ThemeAttr("types", "toml_value")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value")),
                  ThemeStr(",", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value")),
                  ThemeStr("phi", ThemeAttr("types", "toml_value")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value")),
                  ThemeStr("]", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(",", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("[", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr("3.14", ThemeAttr("types", "toml_value")),
                  ThemeStr("]", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("]", ThemeAttr("types", "toml_punctuation"))],
                 [ThemeStr("temp_targets", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("{", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("cpu", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("79.5", ThemeAttr("types", "toml_value")),
                  ThemeStr(",", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("case", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_punctuation")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("72.0", ThemeAttr("types", "toml_value")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("}", ThemeAttr("types", "toml_punctuation"))],
                 [],
                 [ThemeStr("[", ThemeAttr("types", "toml_section")),
                  ThemeStr("servers", ThemeAttr("types", "toml_section")),
                  ThemeStr("]", ThemeAttr("types", "toml_section"))],
                 [],
                 [ThemeStr("[", ThemeAttr("types", "toml_section")),
                  ThemeStr("servers", ThemeAttr("types", "toml_section")),
                  ThemeStr(".", ThemeAttr("types", "toml_section")),
                  ThemeStr("alpha", ThemeAttr("types", "toml_section")),
                  ThemeStr("]", ThemeAttr("types", "toml_section"))]],
                None),
            (
                ["int1 = +99",
                 "int2 = -42",
                 "int3 = 224_617",
                 "hex1 = 0xDEADBEEF",
                 "hex2 = 0xdeadbeef",
                 "hex3 = 0xdead_beef",
                 "oct = 0o755",
                 "bin = 0b11010110",
                 "exp = 6.626e-34",
                 "infinity = inf",
                 "notanumber = nan"],
                {},
                [[ThemeStr("int1", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("+99", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("int2", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("-42", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("int3", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("224_617", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("hex1", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("0xDEADBEEF", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("hex2", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("0xdeadbeef", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("hex3", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("0xdead_beef", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("oct", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("0o755", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("bin", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("0b11010110", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("exp", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("6.626e-34", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("infinity", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("inf", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("notanumber", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("nan", ThemeAttr("types", "toml_value"))]],
                None),
            (
                # Valid but discouraged
                ["'' = \"valid\""],
                {},
                [[ThemeStr("'", ThemeAttr("types", "toml_value")),
                  ThemeStr("'", ThemeAttr("types", "toml_value")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value")),
                  ThemeStr("valid", ThemeAttr("types", "toml_value")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value"))]],
                None),
            (
                # Missing key; pygment still accepts it though
                ["= \"invalid\""],
                {},
                [[ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value")),
                  ThemeStr("invalid", ThemeAttr("types", "toml_value")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value"))]],
                None),
            (
                # Missing value; pygment still accepts it though
                ["invalid ="],
                {},
                [[ThemeStr("invalid", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator"))]],
                None),
            (
                # Escaped characters
                ["test = \"\\\"\""],
                {},
                [[ThemeStr("test", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value")),
                  ThemeStr("\\\"", ThemeAttr("types", "toml_escape")),
                  ThemeStr("\"", ThemeAttr("types", "toml_value"))]],
                None),
            (
                # Multiline string
                ["test = \"\"\"",
                 "Roses are red",
                 "Violets are blue\"\"\""],
                {},
                [[ThemeStr("test", ThemeAttr("types", "toml_key")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("=", ThemeAttr("types", "toml_key_separator")),
                  ThemeStr(" ", ThemeAttr("types", "generic")),
                  ThemeStr("\"\"\"", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("Roses are red", ThemeAttr("types", "toml_value"))],
                 [ThemeStr("Violets are blue", ThemeAttr("types", "toml_value")),
                  ThemeStr("\"\"\"", ThemeAttr("types", "toml_value"))]],
                None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_shellscript(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.format_shellscript

    if result:
        # Indata format:
        # (lines, options, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (
                ["#! /bin/sh",
                 "for file in $( ls ); do",
                 "    printf -- \"Hello World ${file}\\n\"",
                 "done"],
                {},
                [
                    [ThemeStr("#! /bin/sh", ThemeAttr("types", "shellscript_hashbang"))],
                    [ThemeStr("for", ThemeAttr("types", "shellscript_keyword")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("file", ThemeAttr("types", "shellscript_text")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("in", ThemeAttr("types", "shellscript_keyword")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("$(", ThemeAttr("types", "shellscript_keyword")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("ls", ThemeAttr("types", "shellscript_text")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr(")", ThemeAttr("types", "shellscript_keyword")),
                     ThemeStr(";", ThemeAttr("types", "shellscript_punctuation")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("do", ThemeAttr("types", "shellscript_keyword"))],
                    [ThemeStr("    ", ThemeAttr("types", "generic")),
                     ThemeStr("printf", ThemeAttr("types", "shellscript_builtin")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("--", ThemeAttr("types", "shellscript_text")),
                     ThemeStr(" ", ThemeAttr("types", "generic")),
                     ThemeStr("\"", ThemeAttr("types", "shellscript_string")),
                     ThemeStr("Hello World ", ThemeAttr("types", "shellscript_string")),
                     ThemeStr("${", ThemeAttr("types", "shellscript_keyword")),
                     ThemeStr("file", ThemeAttr("types", "shellscript_variable")),
                     ThemeStr("}", ThemeAttr("types", "shellscript_keyword")),
                     ThemeStr("\\n", ThemeAttr("types", "shellscript_string")),
                     ThemeStr("\"", ThemeAttr("types", "shellscript_string"))],
                    [ThemeStr("done", ThemeAttr("types", "shellscript_keyword"))]],
                None),
        )

        for indata, options, expected_result, expected_exception in testdata:
            if isinstance(indata, list):
                indata_quoted = "\n".join(indata)
            else:
                indata_quoted = indata
            indata_quoted = indata_quoted.replace('\n', '\\n')
            try:
                if (tmp := fun(indata, **options)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: \"{indata_quoted}\"\n" \
                                  "         options:\n" \
                                  f"{yaml_dump(options, base_indent=17)}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: \"{indata_quoted}\"\n" \
                              "         options:\n" \
                              f"{yaml_dump(options, base_indent=17)}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_map_dataformat(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.map_dataformat

    if result:
        # Indata format:
        # (kind, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("YAML", formatters.format_yaml, None),
            ("file.yaml", formatters.format_yaml, None),
            ("foo.notarecognisedformat", formatters.format_none, None),
        )

        for indata, expected_result, expected_exception in testdata:
            try:
                # pylint: disable-next=comparison-with-callable
                if (tmp := fun(indata)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: {indata}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           input: {indata}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           input: {indata}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


def test_identify_formatter(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = formatters.identify_formatter

    if result:
        # Indata format:
        # (dataformat, kind, obj, path, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ("foobar", None, None, None, formatters.format_none, None),
            (None, ("ConfigMap", ""), {}, "data", formatters.format_none, None),
            (None,
             ("ConfigMap", ""),
             {
                 "metadata": {
                     "name": "foo",
                     "namespace": "bar",
                 },
                 "data": {
                     "markdown.md": "# Header",
                 },
             }, "markdown.md", formatters.render_markdown, None),
            (None,
             ("ConfigMap", ""),
             {
                 "metadata": {
                     "name": "foo",
                     "namespace": "bar",
                 },
                 "data": {
                     "script": "#! /bin/bash",
                 },
             }, "script", formatters.format_shellscript, None),
            (None,
             ("Secret", ""),
             {
                 "metadata": {
                     "name": "foo",
                     "namespace": "bar",
                 },
                 "data": {
                     "script": "#! /bin/bash",
                 },
             }, "script", None, ValueError),
            (None, ("ConfigMap", ""), None, None, None, ValueError),
            (None, None, {}, None, None, ValueError),
            (None, None, None, "path", None, ValueError),
            (None, None, None, None, None, ValueError),
        )

        for dataformat, kind, obj, path, expected_result, expected_exception in testdata:
            try:
                # pylint: disable-next=comparison-with-callable
                if (tmp := fun(dataformat, kind, obj, path)) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"      dataformat: {dataformat}\n" \
                              f"            kind: {kind}\n" \
                              f"             obj: {obj}\n" \
                              f"            path: {path}\n" \
                              f"          output: {tmp}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"      dataformat: {dataformat}\n" \
                                  f"            kind: {kind}\n" \
                                  f"             obj: {obj}\n" \
                                  f"            path: {path}\n" \
                                  f"       exception: {type(e)}\n" \
                                  f"        expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"      dataformat: {dataformat}\n" \
                              f"            kind: {kind}\n" \
                              f"             obj: {obj}\n" \
                              f"            path: {path}\n" \
                              f"       exception: {type(e)}\n" \
                              f"        expected: {expected_result}"
                    result = False
                    break
    return message, result


tests: dict[tuple[str, ...], dict[str, Any]] = {
    ("format_json_dumps",): {
        "callable": test_json_dumps,
        "result": None,
    },
    ("render_markdown",): {
        "callable": test_render_markdown,
        "result": None,
    },
    ("format_binary",): {
        "callable": test_format_binary,
        "result": None,
    },
    ("format_none",): {
        "callable": test_format_none,
        "result": None,
    },
    ("format_ansible_line",): {
        "callable": test_format_ansible_line,
        "result": None,
    },
    ("format_diff_line",): {
        "callable": test_format_diff_line,
        "result": None,
    },
    ("format_yaml_line",): {
        "callable": test_format_yaml_line,
        "result": None,
    },
    ("format_yaml",): {
        "callable": test_format_yaml,
        "result": None,
    },
    ("reformat_json",): {
        "callable": test_reformat_json,
        "result": None,
    },
    ("format_cel",): {
        "callable": test_format_cel,
        "result": None,
    },
    ("format_crt",): {
        "callable": test_format_crt,
        "result": None,
    },
    ("format_css",): {
        "callable": test_format_css,
        "result": None,
    },
    ("format_diff",): {
        "callable": test_format_diff,
        "result": None,
    },
    ("format_dmesg",): {
        "callable": test_format_dmesg,
        "result": None,
    },
    ("format_docker",): {
        "callable": test_format_docker,
        "result": None,
    },
    ("format_fluentbit",): {
        "callable": test_format_fluentbit,
        "result": None,
    },
    ("format_haproxy",): {
        "callable": test_format_haproxy,
        "result": None,
    },
    ("format_html",): {
        "callable": test_format_html,
        "result": None,
    },
    ("format_ini",): {
        "callable": test_format_ini,
        "result": None,
    },
    ("format_javascript",): {
        "callable": test_format_javascript,
        "result": None,
    },
    ("format_key_value",): {
        "callable": test_format_key_value,
        "result": None,
    },
    ("format_known_hosts",): {
        "callable": test_format_known_hosts,
        "result": None,
    },
    ("format_mosquitto",): {
        "callable": test_format_mosquitto,
        "result": None,
    },
    ("format_nginx",): {
        "callable": test_format_nginx,
        "result": None,
    },
    ("format_xml",): {
        "callable": test_format_xml,
        "result": None,
    },
    ("format_caddyfile",): {
        "callable": test_format_caddyfile,
        "result": None,
    },
    ("format_powershell",): {
        "callable": test_format_powershell,
        "result": None,
    },
    ("format_promql",): {
        "callable": test_format_promql,
        "result": None,
    },
    ("format_python",): {
        "callable": test_format_python,
        "result": None,
    },
    ("format_python_traceback",): {
        "callable": test_format_python_traceback,
        "result": None,
    },
    ("format_toml",): {
        "callable": test_format_toml,
        "result": None,
    },
    ("format_shellscript",): {
        "callable": test_format_shellscript,
        "result": None,
    },
    ("map_dataformat",): {
        "callable": test_map_dataformat,
        "result": None,
    },
    ("identify_formatter",): {
        "callable": test_identify_formatter,
        "result": None,
    },
}


def main() -> int:
    global tests
    global real_import
    real_import = builtins.__import__

    fail = 0
    success = 0
    verbose = False
    failed_testcases = []

    init_ansithemeprint(themefile=None)
    read_theme(DEFAULT_THEME_FILE, DEFAULT_THEME_FILE)

    # How many non-prepare testcases do we have?
    testcount = sum(1 for i in tests if not deep_get(tests[i], DictPath("prepare"), False))

    for i, test in enumerate(tests):
        ansithemeprint([ANSIThemeStr(f"[{i:03}/{testcount - 1:03}]", "emphasis"),
                        ANSIThemeStr(f" {', '.join(test)}:", "default")])
        message, result = tests[test]["callable"](verbose=verbose)
        if message:
            ansithemeprint([ANSIThemeStr("  FAIL", "error"),
                            ANSIThemeStr(f": {message}", "default")])
        else:
            ansithemeprint([ANSIThemeStr("  PASS", "success")])
            success += 1
        tests[test]["result"] = result
        if not result:
            fail += 1
            failed_testcases.append(f"{i}: {', '.join(test)}")

    ansithemeprint([ANSIThemeStr("\nSummary:", "header")])
    if fail:
        ansithemeprint([ANSIThemeStr(f"  FAIL: {fail}", "error")])
    else:
        ansithemeprint([ANSIThemeStr(f"  FAIL: {fail}", "unknown")])
    ansithemeprint([ANSIThemeStr(f"  PASS: {success}", "success")])

    if fail:
        ansithemeprint([ANSIThemeStr("\nFailed testcases:", "header")])
        for testcase in failed_testcases:
            ansithemeprint([ANSIThemeStr("  • ", "separator"),
                            ANSIThemeStr(testcase, "default")], stderr=True)
        sys.exit(fail)

    return 0


if __name__ == "__main__":
    main()
