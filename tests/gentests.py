#! /usr/bin/env python3

# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from datetime import datetime
from pathlib import PurePath
import sys
from typing import Any
import yaml

from clustermanagementtoolkit.cmtpaths import DEFAULT_THEME_FILE

from clustermanagementtoolkit.cmttypes import deep_get, DictPath
from clustermanagementtoolkit.cmttypes import FilePath, ProgrammingError, StatusGroup

from clustermanagementtoolkit import curses_helper
from clustermanagementtoolkit.curses_helper import ThemeAttr, ThemeRef, ThemeStr
from clustermanagementtoolkit.curses_helper import color_status_group

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint, init_ansithemeprint

from clustermanagementtoolkit.cmtlib import none_timestamp

from clustermanagementtoolkit import generators


TEST_DIR = FilePath(PurePath(__file__).parent).joinpath("testpaths")

# unit-tests for generators.py


def yaml_dump(data: Any, base_indent: int = 4) -> str:
    result = ""
    dump = yaml.dump(data)
    for line in dump.splitlines():
        result += f"{' '.ljust(base_indent)}{line}\n"
    return result


def test_callback(options: list[tuple[str, str]], args: list[str]) -> tuple[str, int]:
    return ("callback", len(args))


def test_format_special(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.format_special

    if result:
        # Indata format:
        # (string, selected, expected_result, expected_exception)
        testdata: tuple = (
            (
                "<none>",
                False,
                ThemeStr("<none>", ThemeAttr("types", "none")),
                None,
            ),
            (
                "<unknown>",
                True,
                ThemeStr("<unknown>", ThemeAttr("types", "none"), True),
                None,
            ),
            (
                "<undefined>",
                False,
                ThemeStr("<undefined>", ThemeAttr("types", "undefined")),
                None,
            ),
            (
                "<unspecified>",
                False,
                ThemeStr("<unspecified>", ThemeAttr("types", "undefined")),
                None,
            ),
            (
                "<empty>",
                False,
                ThemeStr("<empty>", ThemeAttr("types", "unset")),
                None,
            ),
            (
                "<unset>",
                False,
                ThemeStr("<unset>", ThemeAttr("types", "unset")),
                None,
            ),
            (
                "<not ready>",
                False,
                ThemeStr("<not ready>", color_status_group(StatusGroup.NOT_OK)),
                None,
            ),
            (
                "<not ready>",
                True,
                ThemeStr("<not ready>", color_status_group(StatusGroup.NOT_OK), True),
                None,
            ),
            (
                "<NOTHING SPECIAL>",
                True,
                None,
                None,
            ),
        )

        for string, selected, expected_result, expected_exception in testdata:
            try:
                tmp = fun(string, selected)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_version(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.format_version

    if result:
        # Indata format:
        # (string, selected, expected_result, expected_exception)
        testdata: tuple = (
            (
                ["v3.14159", "v2.718"],
                False,
                [ThemeStr("v", ThemeAttr("types", "version")),
                 ThemeStr("3", ThemeAttr("types", "numerical")),
                 ThemeStr(".", ThemeAttr("types", "unit")),
                 ThemeStr("14159", ThemeAttr("types", "numerical")),
                 ThemeRef('separators', 'list', False),
                 ThemeStr("v", ThemeAttr("types", "version")),
                 ThemeStr("2", ThemeAttr("types", "numerical")),
                 ThemeStr(".", ThemeAttr("types", "unit")),
                 ThemeStr("718", ThemeAttr("types", "numerical"))],
                None,
            ),
            (
                "3.14159~beta1",
                False,
                [ThemeStr("3", ThemeAttr("types", "numerical")),
                 ThemeStr(".", ThemeAttr("types", "unit")),
                 ThemeStr("14159", ThemeAttr("types", "numerical")),
                 ThemeStr("~", ThemeAttr("types", "unit")),
                 ThemeStr("beta1", ThemeAttr("types", "numerical"))],
                None,
            ),
            (
                [""],
                False,
                [], None,
            ),
        )

        for string, selected, expected_result, expected_exception in testdata:
            try:
                tmp = fun(string, selected)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_timestamp(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.format_timestamp

    if result:
        # Indata format:
        # (string, selected, expected_result, expected_exception)
        testdata: tuple = (
            (
                "<none>",
                False,
                [ThemeStr("<none>", ThemeAttr("types", "none"))],
                None,
            ),
            (
                "2026-01-01 12:13:14",
                False,
                [ThemeStr('2026', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('-', ThemeAttr('types', 'unit'), False),
                 ThemeStr('01', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('-', ThemeAttr('types', 'unit'), False),
                 ThemeStr('01', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(' ', ThemeAttr('types', 'unit'), False),
                 ThemeStr('12', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('13', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('14', ThemeAttr('types', 'numerical'), False)],
                None,
            ),
            (
                datetime(2026, 1, 1, 12, 13, 14, 0),
                False,
                [ThemeStr('2026', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('-', ThemeAttr('types', 'unit'), False),
                 ThemeStr('01', ThemeAttr('types', 'numerical'), False),
                 ThemeStr('-', ThemeAttr('types', 'unit'), False),
                 ThemeStr('01', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(' ', ThemeAttr('types', 'unit'), False),
                 ThemeStr('12', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('13', ThemeAttr('types', 'numerical'), False),
                 ThemeStr(':', ThemeAttr('types', 'unit'), False),
                 ThemeStr('14', ThemeAttr('types', 'numerical'), False)],
                None,
            ),
            (
                none_timestamp(),
                False,
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                None,
            ),
            (
                "",
                False,
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                None,
            ),
            (
                None,
                False,
                [ThemeStr('', ThemeAttr('types', 'generic'), False)],
                None,
            ),
        )

        for string, selected, expected_result, expected_exception in testdata:
            try:
                tmp = fun(string, selected)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_map_value(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.map_value

    if result:
        # Indata format:
        # (value, selected, default_field_color, kwargs, expected_result, expected_exception)
        testdata: tuple = (
            (
                "1",
                False,
                ThemeAttr("types", "numerical"),
                {},
                (ThemeStr("1", ThemeAttr("types", "numerical"), False), "1"),
                None,
            ),
            (
                "Foo",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "substitutions": {
                            "Foo": {
                                "context": "main",
                                "type": "status_ok",
                                "string": "yay",
                            },
                        },
                    },
                },
                (ThemeStr("yay", ThemeAttr("main", "status_ok"), False), "yay"),
                None,
            ),
            (
                "Foo",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "substitutions": {
                            "Foo": ThemeRef("strings", "positive_check", False),
                        },
                    },
                },
                (ThemeRef("strings", "positive_check", False), "✓"),
                None,
            ),
            (
                "True",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "substitutions": {
                            "True": {
                                "context": "strings",
                                "type": "positive_check",
                            },
                            "False": {
                                "context": "strings",
                                "type": "negative_ballot",
                            }
                        },
                    },
                },
                (ThemeRef("strings", "positive_check", False), "✓"),
                None,
            ),
            (
                "False",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "substitutions": {
                            "True": {
                                "context": "strings",
                                "type": "positive_check",
                            },
                            "False": {
                                "context": "strings",
                                "type": "negative_ballot",
                            }
                        },
                    },
                },
                (ThemeRef("strings", "negative_ballot", False), "✗"),
                None,
            ),
            (
                0,
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "substitutions": {
                            "__0": {
                                "context": "strings",
                                "type": "positive_check",
                            },
                            "__1": {
                                "context": "strings",
                                "type": "negative_ballot",
                            }
                        },
                    },
                },
                (ThemeRef("strings", "positive_check", False), "✓"),
                None,
            ),
            (
                1,
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "substitutions": {
                            "__0": {
                                "context": "strings",
                                "type": "positive_check",
                            },
                            "__1": {
                                "context": "strings",
                                "type": "negative_ballot",
                            }
                        },
                    },
                },
                (ThemeRef("strings", "negative_ballot", False), "✗"),
                None,
            ),
            (
                "Foo",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "mappings": {
                            "Foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "generic",
                                    },
                                ]
                            },
                            "foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "numerical",
                                    },
                                ]
                            }
                        },
                    },
                },
                (ThemeStr("Foo", ThemeAttr("types", "generic"), False), "Foo"),
                None,
            ),
            (
                "foo",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "mappings": {
                            "Foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "generic",
                                    },
                                ]
                            },
                            "foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "numerical",
                                    },
                                ]
                            }
                        },
                    },
                },
                (ThemeStr("foo", ThemeAttr("types", "numerical"), False), "foo"),
                None,
            ),
            (
                "Foo",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "match_case": False,
                        "mappings": {
                            "foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "numerical",
                                    },
                                ]
                            }
                        },
                    },
                },
                (ThemeStr("Foo", ThemeAttr("types", "numerical"), False), "Foo"),
                None,
            ),
            (
                "Foo",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "match_case": False,
                        "mappings": {
                            "Foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "generic",
                                    },
                                ]
                            },
                            "foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "numerical",
                                    },
                                ]
                            }
                        },
                    },
                },
                None,
                ValueError,
            ),
            # Unsupported type
            (
                {"foo", "bar"},
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "match_case": False,
                        "mappings": {
                            "Foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "generic",
                                    },
                                ]
                            },
                            "foo": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "numerical",
                                    },
                                ]
                            }
                        },
                    },
                },
                None,
                TypeError,
            ),
            (
                "1",
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "mappings": {
                            "1": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "numerical",
                                    },
                                ]
                            }
                        },
                    },
                },
                (ThemeStr("1", ThemeAttr("types", "numerical"), False), "1"),
                None,
            ),
            (
                1,
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "mappings": {
                            "1": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "numerical",
                                    },
                                ]
                            }
                        },
                    },
                },
                (ThemeStr("1", ThemeAttr("types", "numerical"), False), "1"),
                None,
            ),
            (
                0,
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "ranges": [
                            {
                                "min": 0,
                                "max": 1,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_ok",
                                    },
                                ]
                            },
                            {
                                "default": True,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_not_ok",
                                    },
                                ]
                            },
                        ],
                    },
                },
                (ThemeStr("0", ThemeAttr("main", "status_ok"), False), "0"),
                None,
            ),
            (
                0,
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "ranges": [
                            {
                                "default": True,
                                "min": 0,
                                "max": 1,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_ok",
                                    },
                                ]
                            },
                            {
                                "default": True,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_not_ok",
                                    },
                                ]
                            },
                        ],
                    },
                },
                None,
                ValueError,
            ),
            (
                1,
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "ranges": [
                            {
                                "min": 0,
                                "max": 1,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_ok",
                                    },
                                ]
                            },
                            {
                                "default": True,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_not_ok",
                                    },
                                ]
                            },
                        ],
                    },
                },
                (ThemeStr("1", ThemeAttr("main", "status_not_ok"), False), "1"),
                None,
            ),
            (
                (0, 1),
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "ranges": [
                            {
                                "min": 0,
                                "max": 1,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_ok",
                                    },
                                ]
                            },
                            {
                                "default": True,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_not_ok",
                                    },
                                ]
                            },
                        ],
                    },
                },
                (ThemeStr("0", ThemeAttr("main", "status_not_ok"), False), "0"),
                None,
            ),
            (
                (1, 0),
                False,
                ThemeAttr("types", "numerical"),
                {
                    "mapping": {
                        "ranges": [
                            {
                                "min": 0,
                                "max": 1,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_ok",
                                    },
                                ]
                            },
                            {
                                "default": True,
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_not_ok",
                                    },
                                ]
                            },
                        ],
                    },
                },
                (ThemeStr("1", ThemeAttr("main", "status_ok"), False), "1"),
                None,
            ),
        )

        for value, selected, default_field_color, kwargs, \
                expected_result, expected_exception in testdata:
            try:
                tmp = fun(value=value, selected=selected,
                          default_field_color=default_field_color, **kwargs)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_align_and_pad(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.align_and_pad

    if result:
        # Indata format:
        # (themearray, pad, fieldlen, ralign, selected, expected_result, expected_exception)
        testdata: tuple = (
            (
                [
                    ThemeStr("Foo", ThemeAttr("main", "default")),
                ],
                True,
                8,
                False,
                False,
                [
                    ThemeStr("Foo", ThemeAttr("main", "default"), False),
                    ThemeStr("     ", ThemeAttr("types", "generic"), False),
                    ThemeRef("separators", "pad", False)
                ],
                None,
            ),
            (
                [
                    ThemeStr("Foo", ThemeAttr("main", "default")),
                ],
                False,
                0,
                False,
                False,
                [
                    ThemeStr("Foo", ThemeAttr("main", "default"), False),
                    ThemeStr("", ThemeAttr("types", "generic"), False),
                ],
                None,
            ),
            (
                [
                    ThemeStr("Foo", ThemeAttr("main", "default")),
                ],
                True,
                4,
                False,
                False,
                [
                    ThemeStr("Foo", ThemeAttr("main", "default"), False),
                    ThemeStr(" ", ThemeAttr("types", "generic"), False),
                    ThemeRef("separators", "pad", False)
                ],
                None,
            ),
            (
                [
                    ThemeStr("Foo", ThemeAttr("main", "default")),
                ],
                True,
                6,
                True,
                False,
                [
                    ThemeStr("   ", ThemeAttr("types", "generic"), False),
                    ThemeStr("Foo", ThemeAttr("main", "default"), False),
                    ThemeRef("separators", "pad", False)
                ],
                None,
            ),
        )

        for themearray, pad, fieldlen, ralign, \
                selected, expected_result, expected_exception in testdata:
            try:
                tmp = fun(themearray, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_address(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.format_address

    if result:
        # Indata format:
        # ([str], selected, expected_result, expected_exception)
        testdata: tuple = (
            # IPv4
            (
                ["127.0.0.1"],
                False,
                [ThemeStr("127", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("1", ThemeAttr("types", "address"))],
                None,
            ),
            # IPv4, IPv4
            (
                ["127.0.0.1", "192.168.0.1"],
                False,
                [ThemeStr("127", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("1", ThemeAttr("types", "address")),
                 ThemeRef("separators", "list"),
                 ThemeStr("192", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("168", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("1", ThemeAttr("types", "address"))],
                None,
            ),
            # IPv4, string
            (
                "127.0.0.1",
                False,
                [ThemeStr("127", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("1", ThemeAttr("types", "address"))],
                None,
            ),
            # IPv4 with mask
            (
                ["127.0.0.0/24"],
                False,
                [ThemeStr("127", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipmask"),
                 ThemeStr("24", ThemeAttr("types", "ipmask"))],
                None,
            ),
            # IPv6 with mask
            (
                ["64:ff9b::127.0.0.1/128"],
                False,
                [ThemeStr("64", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv6address"),
                 ThemeStr("ff9b", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv6address"),
                 ThemeRef("separators", "ipv6address"),
                 ThemeStr("127", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("0", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("1", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipmask"),
                 ThemeStr("128", ThemeAttr("types", "ipmask"))],
                None,
            ),
        )

        for string, selected, expected_result, expected_exception in testdata:
            try:
                tmp = fun(string, selected)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_uri(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.format_uri

    if result:
        # Indata format:
        # ([str], selected, expected_result, expected_exception)
        testdata: tuple = (
            # Valid URI
            (
                "http://example.org/foobar.html",
                False,
                [ThemeStr("http", ThemeAttr("types", "protocol")),
                 ThemeRef("separators", "uri_separator"),
                 ThemeStr("example", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("org", ThemeAttr("types", "address")),
                 ThemeRef("separators", "uri_path"),
                 ThemeStr("foobar.html", ThemeAttr("types", "address"))],
                None,
            ),
            # Valid URI with port
            (
                "http://example.org:6581",
                False,
                [ThemeStr("http", ThemeAttr("types", "protocol")),
                 ThemeRef("separators", "uri_separator"),
                 ThemeStr("example", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("org", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv6address"),
                 ThemeStr("6581", ThemeAttr("types", "address"))],
                None,
            ),
            # Valid URI with multiple segments
            (
                "http://example.org/foo/bar.html",
                False,
                [ThemeStr("http", ThemeAttr("types", "protocol")),
                 ThemeRef("separators", "uri_separator"),
                 ThemeStr("example", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("org", ThemeAttr("types", "address")),
                 ThemeRef("separators", "uri_path"),
                 ThemeStr("foo", ThemeAttr("types", "address")),
                 ThemeRef("separators", "uri_path"),
                 ThemeStr("bar.html", ThemeAttr("types", "address"))],
                None,
            ),
            # Valid URI, split
            (
                ("http", "://", "example.org/foobar.html"),
                False,
                [ThemeStr("http", ThemeAttr("types", "protocol")),
                 ThemeRef("separators", "uri_separator"),
                 ThemeStr("example", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("org", ThemeAttr("types", "address")),
                 ThemeRef("separators", "uri_path"),
                 ThemeStr("foobar.html", ThemeAttr("types", "address"))],
                None,
            ),
            # Multiple valid URIs
            (
                ["http://example1.org", "https://example2.net"],
                False,
                [ThemeStr("http", ThemeAttr("types", "protocol")),
                 ThemeRef("separators", "uri_separator"),
                 ThemeStr("example1", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("org", ThemeAttr("types", "address")),
                 ThemeRef("separators", "list"),
                 ThemeStr("https", ThemeAttr("types", "protocol")),
                 ThemeRef("separators", "uri_separator"),
                 ThemeStr("example2", ThemeAttr("types", "address")),
                 ThemeRef("separators", "ipv4address"),
                 ThemeStr("net", ThemeAttr("types", "address"))],
                None,
            ),
            # Invalid URI
            (
                ["foobar"],
                False,
                [ThemeStr("foobar", ThemeAttr("types", "generic"))],
                None,
            ),
            # Invalid URI
            (
                "http://example.org:6581:",
                False,
                [ThemeStr("http://example.org:6581:", ThemeAttr("types", "generic"))],
                None,
            ),
            # empty data
            (
                [],
                False,
                [ThemeStr("", ThemeAttr("types", "generic"))],
                None,
            ),
        )

        for string, selected, expected_result, expected_exception in testdata:
            try:
                tmp = fun(string, selected)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_generator_value_mapper(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.generator_value_mapper

    if result:
        # Indata format:
        # (obj, field, expected_result, expected_exception)
        testdata: tuple = (
            (
                {
                    "state": "Completed",
                },
                "state",
                9,
                2,
                False,
                True,
                {
                    "item_separator": ThemeRef("separators", "list", False),
                    "field_separators": [
                        ThemeRef("separators", "field", False),
                    ],
                    "field_colors": [
                        ThemeAttr("types", "field")
                    ],
                    "ellipsise": -1,
                    "ellipsis": ThemeRef("separators", "ellipsis", False),
                    "field_prefixes": [],
                    "field_suffixes": [],
                    "mapping": {
                        "mappings": {
                            "Active": {
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_pending",
                                    },
                                ],
                            },
                            "Completed": {
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_done",
                                    },
                                ],
                            },
                            "Running": {
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_ok",
                                    },
                                ],
                            },
                            "<unset>": {
                                "field_colors": [
                                    {
                                        "context": "types",
                                        "type": "unset",
                                    },
                                ],
                            },
                            "__default": {
                                "field_colors": [
                                    {
                                        "context": "main",
                                        "type": "status_not_ok",
                                    },
                                ],
                            },
                        },
                    },
                    "field_formatters": [],
                },
                [
                    ThemeStr("Completed", ThemeAttr("main", "status_done"), True),
                    ThemeStr("", ThemeAttr("types", "generic"), True),
                    ThemeRef("separators", "pad", True)
                ],
                None,
            ),
        )

        for obj, field, fieldlen, pad, ralign, selected, formatting, \
                expected_result, expected_exception in testdata:
            try:
                tmp = fun(obj, field, fieldlen, pad, ralign, selected, **formatting)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_get_formatting(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.get_formatting

    if result:
        # Indata format:
        # (field, formatting, default, expected_result, expected_exception)
        testdata: tuple = (
            (
                {"formatting": {"foo": {"context": "foo"}}},
                "foo",
                {"foo": "bar"},
                None,
                ProgrammingError,
            ),
            (
                {},
                "foo",
                {"foo": "bar"},
                "bar",
                None,
            ),
            (
                {"formatting": {"foo": 42}},
                "foo",
                {"foo": "bar"},
                None,
                TypeError,
            ),
            (
                {"formatting": {"foo": [ThemeAttr("types", "age")]}},
                "foo",
                None,
                None,
                ValueError,
            ),
            (
                {"formatting": {"foo": []}},
                "foo",
                {"foo": "bar"},
                None,
                ValueError,
            ),
            (
                {"formatting": {"foo": [42]}},
                "foo",
                {"foo": "bar"},
                None,
                TypeError,
            ),
            (
                {"formatting": {"foo": [{"context": "foo"}, 42]}},
                "foo",
                {"foo": "bar"},
                None,
                TypeError,
            ),
            (
                {"formatting": {"ellipsis": [{"type": "ellipsis"}]}},
                "ellipsis",
                {"foo": "bar"},
                [ThemeRef('separators', 'ellipsis')],
                None,
            ),
            (
                {"formatting": {"ellipsis": [ThemeRef("separators", "ellipsis")]}},
                "ellipsis",
                {"foo": "bar"},
                [ThemeRef('separators', 'ellipsis')],
                None,
            ),
        )

        for field, formatting, default, expected_result, expected_exception in testdata:
            try:
                tmp = fun(field, formatting, default)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_get_formatter(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = generators.get_formatter

    if result:
        # Indata format:
        # (field, expected_result, expected_exception)
        testdata: tuple = (
            (
                {
                    "formatting": {
                        "field_colors": [{"type": "namespace"}],
                    },
                },
                {
                    "generator": generators.generator_basic,
                    'formatting': {
                        'args': {},
                        'item_separator': ThemeRef('separators', 'list'),
                        'field_separators': [ThemeRef('separators', 'field')],
                        'field_colors': [ThemeAttr('types', 'namespace')],
                        'ellipsise': -1,
                        'ellipsis': ThemeRef('separators', 'ellipsis'),
                        'field_prefixes': [],
                        'field_suffixes': [],
                        'mapping': {},
                        'field_formatters': [],
                        'unit': '',
                    }
                },
                None,
            ),
            (
                {
                    "type": "age",
                },
                {
                    "generator": generators.generator_basic,
                    'formatting': {
                        'args': {},
                        'item_separator': ThemeRef('separators', 'list'),
                        'field_separators': [ThemeRef('separators', 'field')],
                        'field_colors': [ThemeAttr('types', 'age')],
                        'ellipsise': -1,
                        'ellipsis': ThemeRef('separators', 'ellipsis'),
                        'field_prefixes': [],
                        'field_suffixes': [],
                        'mapping': {},
                        'field_formatters': [],
                        'unit': '',
                    }
                },
                None,
            ),
            (
                {
                    "generator": generators.generator_numerical_with_units,
                    "align": "right",
                },
                {
                    "generator": generators.generator_numerical_with_units,
                    'ralign': True,
                    'formatting': {
                        'args': {},
                        'item_separator': ThemeRef('separators', 'list'),
                        'field_separators': [ThemeRef('separators', 'field')],
                        'field_colors': [ThemeAttr('types', 'field')],
                        'ellipsise': -1,
                        'ellipsis': ThemeRef('separators', 'ellipsis'),
                        'field_prefixes': [],
                        'field_suffixes': [],
                        'mapping': {},
                        'field_formatters': [],
                        'unit': '',
                    }
                },
                None,
            ),
            (
                {
                    "generator": generators.generator_status,
                },
                {
                    "generator": generators.generator_status,
                    'formatting': {
                        'args': {},
                        'item_separator': ThemeRef('separators', 'list'),
                        'field_separators': [ThemeRef('separators', 'field')],
                        'field_colors': [ThemeAttr('types', 'field')],
                        'ellipsise': -1,
                        'ellipsis': ThemeRef('separators', 'ellipsis'),
                        'field_prefixes': [],
                        'field_suffixes': [],
                        'mapping': {},
                        'field_formatters': [],
                        'unit': '',
                    }
                },
                None,
            ),
            (
                {
                    "formatter": "address",
                },
                {
                    "generator": generators.generator_address,
                    'formatting': {
                        'args': {},
                        'item_separator': ThemeRef('separators', 'list'),
                        'field_separators': [],
                        'field_colors': [ThemeAttr('types', 'field')],
                        'ellipsise': -1,
                        'ellipsis': ThemeRef('separators', 'ellipsis'),
                        'field_prefixes': [],
                        'field_suffixes': [],
                        'mapping': {},
                        'field_formatters': [],
                        'unit': '',
                    }
                },
                None,
            ),
            (
                {
                    "formatter": "notavalidformatter",
                },
                None,
                ProgrammingError,
            ),
        )

        for field, expected_result, expected_exception in testdata:
            try:
                tmp = fun(field)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {str(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {str(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


tests: dict[tuple[str], dict[str, Any]] = {
    ("format_special()",): {
        "callable": test_format_special,
        "result": None,
    },
    ("format_version()",): {
        "callable": test_format_version,
        "result": None,
    },
    ("format_timestamp()",): {
        "callable": test_format_timestamp,
        "result": None,
    },
    ("map_value()",): {
        "callable": test_map_value,
        "result": None,
    },
    ("align_and_pad()",): {
        "callable": test_align_and_pad,
        "result": None,
    },
    ("format_address()",): {
        "callable": test_format_address,
        "result": None,
    },
    ("format_uri()",): {
        "callable": test_format_uri,
        "result": None,
    },
    ("generator_value_mapper()",): {
        "callable": test_generator_value_mapper,
        "result": None,
    },
    ("get_formatting()",): {
        "callable": test_get_formatting,
        "result": None,
    },
    ("get_formatter()",): {
        "callable": test_get_formatter,
        "result": None,
    },
}


def main() -> int:
    fail = 0
    success = 0
    verbose = False
    failed_testcases = []

    themefile = DEFAULT_THEME_FILE
    init_ansithemeprint(themefile=themefile)
    curses_helper.read_theme(themefile, themefile)

    # How many non-prepare testcases do we have?
    testcount = sum(1 for i in tests if not deep_get(tests[i], DictPath("prepare"), False))
    start_at_task = 0
    end_at_task = testcount

    i = 1

    while i < len(sys.argv):
        opt = sys.argv[i]
        optarg = None
        if i + 1 < len(sys.argv):
            optarg = sys.argv[i + 1]
        if opt == "--start-at":
            if not (isinstance(optarg, str) and optarg.isnumeric()):
                raise ValueError("--start-at TASK requires an integer "
                                 f"in the range [0,{testcount}]")
            start_at_task = int(optarg)
            i += 1
        elif opt == "--end-at":
            if not (isinstance(optarg, str) and optarg.isnumeric()):
                raise ValueError(f"--end-at TASK requires an integer in the range [0,{testcount}]")
            end_at_task = int(optarg)
            i += 1
        else:
            sys.exit(f"Unknown argument: {opt}")
        i += 1

    for i, test in enumerate(tests):
        if i < start_at_task:
            continue
        if i > end_at_task:
            break
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
