#! /usr/bin/env python3

# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import copy
import curses
import os
from pathlib import PurePath
import sys
from typing import Any
from unittest import mock
import yaml

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmtio import expand_path

from clustermanagementtoolkit.cmtpaths import DEFAULT_THEME_FILE
from clustermanagementtoolkit.cmtpaths import THEMES_DIR

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint
from clustermanagementtoolkit.ansithemeprint import init_ansithemeprint

from clustermanagementtoolkit import curses_helper
from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import ThemeArray
from clustermanagementtoolkit.curses_helper import WidgetLineAttrs

TEST_DIR = str(PurePath(__file__).parent.joinpath("testthemes"))


def yaml_dump(data: Any, base_indent: int = 4) -> str:
    result = ""
    dump = yaml.dump(data)
    for line in dump.splitlines():
        result += f"{' '.ljust(base_indent)}{line}\n"
    return result


def test_themestring(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.ThemeStr

    if result:
        try:
            themeattr = ThemeAttr("types", "generic")
            if repr(themeattr) != "ThemeAttr('types', 'generic')":
                message = f"ThemeAttr() did not yield expected result:\n" \
                          f"          input: (\"types\", \"generic\")\n" \
                          f"         output: {repr(themeattr)}\n" \
                          f"       expected: ThemeAttr('types', 'generic')"
                result = False
        except Exception as e:
            message = f"ThemeAttr() did not yield expected result:\n" \
                      f"          input: (\"types\", \"generic\")\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: ThemeAttr('types', 'generic')"
            result = False

    if result:
        try:
            # ThemeAttr shouldn't check if the context/key pair exists
            themeattr = ThemeAttr("types", "DOESNOTEXIST")
            if repr(themeattr) != "ThemeAttr('types', 'DOESNOTEXIST')":
                message = f"ThemeAttr() did not yield expected result:\n" \
                          f"          input: ('types', 'DOESNOTEXIST')\n" \
                          f"         output: {repr(themeattr)}\n" \
                          f"       expected: ThemeAttr('types', 'DOESNOTEXIST')"
                result = False
        except Exception as e:
            message = f"ThemeAttr() did not yield expected result:\n" \
                      f"          input: (\"types\", \"generic\")\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: ThemeAttr('types', 'DOESNOTEXIST')"
            result = False

    if result:
        # Indata format:
        testdata: tuple[Any, ...] = (
            ("A test string", ThemeAttr("types", "generic"),
             "ThemeStr('A test string', ThemeAttr('types', 'generic'), False)", None),
            (None, ThemeAttr("types", "generic"),
             None, ProgrammingError),
        )
        for indata, themeattr, expected_result, expected_exception in testdata:
            try:
                tmp = fun(indata, themeattr)
                if repr(tmp) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"         output: {repr(tmp)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"          input: {indata}\n" \
                                  f"      exception: {type(e)}\n" \
                                  f"       expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"      exception: {type(e)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break

    if result:
        indata = ThemeStr("123", ThemeAttr("types", "generic"))
        tmp = len(indata)
        if tmp != 3:
            message = f"{fun.__name__}.__len__() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: 3"
            result = False

    if result:
        str1 = ThemeStr("123", ThemeAttr("types", "generic"))
        str2 = ThemeStr("124", ThemeAttr("types", "generic"))
        tmp = str1 == str2
        if tmp:
            message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                      f"          input: {repr(str1)} == {repr(str2)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: False"
            result = False

    if result:
        str1 = ThemeStr("123", ThemeAttr("types", "generic"))
        str2 = ThemeStr("123", ThemeAttr("types", "generic"))
        tmp = str1 == str2
        if not tmp:
            message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                      f"          input: {repr(str1)} == {repr(str2)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: True"
            result = False

    if result:
        indata = ThemeStr("123", ThemeAttr("types", "generic"))
        tmp = str(indata)
        if tmp != "123":
            message = f"{fun.__name__}.__str__() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: 123"
            result = False

    if result:
        str1 = ThemeStr("123", ThemeAttr("types", "generic"))
        str2 = "a"
        tmp = str1 == str2
        if tmp:
            message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                      f"          input: {repr(str1)} == {repr(str2)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: False"
            result = False

    if result:
        indata = ThemeStr("123", ThemeAttr("types", "generic"))
        try:
            tmp = indata.get_themeattr()
            if tmp != ThemeAttr("types", "generic"):
                message = f"ThemeAttr() did not yield expected result:\n" \
                          f"          input: {repr(indata)}\n" \
                          f"         output: {repr(tmp)}\n" \
                          f"       expected: ThemeAttr('types', 'generic')"
                result = False
        except Exception as e:
            message = f"{fun.__name__}.get_themeattr() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: ThemeAttr('types', 'generic')"
            result = False

    if result:
        indata = ThemeStr("http://www.intel.com", ThemeAttr("types", "generic"))
        try:
            indata.set_themeattr(ThemeAttr("types", "url"))
            tmp = indata.get_themeattr()
            if tmp != ThemeAttr("types", "url"):
                message = f"{fun.__name__}.set_themeattr() did not yield expected result:\n" \
                          f"          input: {repr(indata)}\n" \
                          f"         output: {repr(tmp)}\n" \
                          f"       expected: ThemeAttr('types', 'url')"
                result = False
        except Exception as e:
            message = f"{fun.__name__}.set_themeattr() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: ThemeAttr('types', 'url')"
            result = False

    if result:
        indata = ThemeStr("1", ThemeAttr("types", "generic"), True)
        try:
            tmp = indata.get_selected()
            if not tmp:
                message = f"{fun.__name__}.get_selected() did not yield expected result:\n" \
                          f"          input: {repr(indata)}\n" \
                          f"         output: {tmp}\n" \
                          f"       expected: True"
                result = False
        except Exception as e:
            message = f"{fun.__name__}.get_selected() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: True"
            result = False

    return message, result


def test_themeref(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.ThemeRef

    if result:
        # Indata format:
        testdata: tuple[Any, ...] = (
            (("strings", "none"),
             "ThemeRef('strings', 'none', False)", None),
            ((None, "none"),
             None, ProgrammingError),
        )
        for indata, expected_result, expected_exception in testdata:
            try:
                tmp = fun(indata[0], indata[1])
                if repr(tmp) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"         output: {repr(tmp)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"          input: {indata}\n" \
                                  f"      exception: {type(e)}\n" \
                                  f"       expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"      exception: {type(e)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break

    if result:
        indata = ThemeRef("strings", "status_critical", False)
        tmp = str(indata)
        if tmp != "■":
            message = f"{fun.__name__}.__str__() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: ■"
            result = False

    if result:
        indata = ThemeRef("strings", "status_critical", True)
        tmp = str(indata)
        if tmp != "█":
            message = f"{fun.__name__}.__str__() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: █"
            result = False

    if result:
        indata = ThemeRef("nonexisting", "themeref", True)
        try:
            tmp = str(indata)
            if tmp != "<themeref missing>":
                message = f"{fun.__name__}(\"nonexisting\", \"themeref\") did not yield " \
                          "expected result:\n" \
                          f"         output: \"{tmp}\"\n" \
                          "       expected: \"<themeref missing>\""
                result = False
        except Exception as e:
            if isinstance(e, ProgrammingError):
                pass
            else:
                message = f"{fun.__name__}(\"nonexisting\", \"themeref\") did not yield " \
                          "expected result:\n" \
                          "       expected: \"<themeref missing>\""
                result = False

    if result:
        indata = ThemeRef("strings", "status_critical", True)
        tmp = len(indata)
        if tmp != 1:
            message = f"{fun.__name__}.__str__() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: 1"
            result = False

    if result:
        indata = ThemeRef("strings", "status_critical", False)
        try:
            tmp = indata.to_themearray()
            if repr(tmp) != "[ThemeStr('■', ThemeAttr('main', 'status_critical'), False)]":
                message = f"{fun.__name__}.to_themearray() did not yield expected result:\n" \
                          f"          input: {repr(indata)}\n" \
                          f"         output: {repr(tmp)}\n" \
                          f"       expected: " \
                          "[ThemeStr('■', ThemeAttr('main', 'status_critical'), False)]"
                result = False
        except Exception as e:
            message = f"{fun.__name__}.top_themearray() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: " \
                      "[ThemeStr('■', ThemeAttr('main', 'status_critical'), False)]"
            result = False

    if result:
        indata = ThemeRef("strings", "status_critical", True)
        try:
            tmp = indata.to_themearray()
            if repr(tmp) != "[ThemeStr('█', ThemeAttr('main', 'status_critical'), True)]":
                message = f"{fun.__name__}.to_themearray() did not yield expected result:\n" \
                          f"          input: {repr(indata)}\n" \
                          f"         output: {repr(tmp)}\n" \
                          f"       expected: " \
                          "[ThemeStr('■', ThemeAttr('main', 'status_critical'), True)]"
                result = False
        except Exception as e:
            message = f"{fun.__name__}.top_themearray() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: " \
                      "[ThemeStr('█', ThemeAttr('main', 'status_critical'), True)]"

            result = False

    if result:
        indata = ThemeRef("", "", True)
        try:
            tmp = indata.to_themearray()
            message = f"{fun.__name__}.to_themearray() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"         output: {repr(tmp)}\n" \
                      f"       expected: {ProgrammingError}"
            result = False
        except Exception as e:
            if not isinstance(e, ProgrammingError):
                message = f"{fun.__name__}.top_themearray() did not yield expected result:\n" \
                          f"          input: {repr(indata)}\n" \
                          f"      exception: {type(e)}\n" \
                          f"       expected: {ProgrammingError}"
                result = False

    if result:
        indata = ThemeRef("strings", "status_critical", False)
        try:
            tmp = indata.get_selected()
            if tmp:
                message = f"{fun.__name__}.get_selected() did not yield expected result:\n" \
                          f"          input: {repr(indata)}\n" \
                          f"         output: {tmp}\n" \
                          f"       expected: True"
                result = False
        except Exception as e:
            message = f"{fun.__name__}.get_selected() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: True"
            result = False

    if result:
        indata = ThemeRef("strings", "status_critical", True)
        try:
            tmp = indata.get_selected()
            if not tmp:
                message = f"{fun.__name__}.get_selected() did not yield expected result:\n" \
                          f"          input: {repr(indata)}\n" \
                          f"         output: {tmp}\n" \
                          f"       expected: False"
                result = False
        except Exception as e:
            message = f"{fun.__name__}.get_selected() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"      exception: {type(e)}\n" \
                      f"       expected: True"
            result = False

    if result:
        indata1 = ThemeRef("strings", "status_critical", False)
        indata2 = ThemeRef("strings", "status_critical", True)
        tmp = indata1 == indata2
        if tmp:
            message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                      f"          input: {repr(indata1)} == {repr(indata2)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: False"
            result = False

    if result:
        indata1 = ThemeRef("strings", "status_critical", False)
        indata2 = ThemeRef("strings", "status_critical", False)
        tmp = indata1 == indata2
        if not tmp:
            message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                      f"          input: {repr(indata1)} == {repr(indata2)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: True"
            result = False

    if result:
        indata1 = ThemeRef("strings", "status_critical", False)
        indata2 = 42
        tmp = indata1 == indata2
        if tmp:
            message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                      f"          input: {repr(indata1)} == {repr(indata2)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: False"
            result = False

    return message, result


def test_themearray(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.ThemeArray

    if result:
        # Indata format:
        testdata: tuple[Any, ...] = (
            ([ThemeStr("Hello ", ThemeAttr("types", "generic")),
              ThemeStr("World", ThemeAttr("types", "emphasis"))], False,
             "ThemeArray([ThemeStr('Hello ', ThemeAttr('types', 'generic'), False), "
             "ThemeStr('World', ThemeAttr('types', 'emphasis'), False)])", None),
            ([ThemeStr("Hello ", ThemeAttr("types", "generic"), False),
              ThemeStr("World", ThemeAttr("types", "emphasis"), False)], True,
             "ThemeArray([ThemeStr('Hello ', ThemeAttr('types', 'generic'), True), "
             "ThemeStr('World', ThemeAttr('types', 'emphasis'), True)])", None),
            ([ThemeStr("Hello ", ThemeAttr("types", "generic")),
              ThemeStr("World", ThemeAttr("types", "emphasis"))], None,
             "ThemeArray([ThemeStr('Hello ', ThemeAttr('types', 'generic'), False), "
             "ThemeStr('World', ThemeAttr('types', 'emphasis'), False)])", None),
            ([ThemeStr("Hello ", ThemeAttr("types", "generic")),
              ThemeStr("World", ThemeAttr("types", "emphasis")),
              ThemeRef("separators", "matchbullet")], False,
             "ThemeArray([ThemeStr('Hello ', ThemeAttr('types', 'generic'), False), "
             "ThemeStr('World', ThemeAttr('types', 'emphasis'), False), "
             "ThemeRef('separators', 'matchbullet', False)])", None),
            (None, False, None, ProgrammingError),
            ("a", False, None, ProgrammingError),
            (["a"], False, None, ProgrammingError),
        )
        for indata, selected, expected_result, expected_exception in testdata:
            try:
                tmp = fun(indata, selected)
                if repr(tmp) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"         output: {repr(tmp)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"          input: {indata}\n" \
                                  f"      exception: {type(e)}\n" \
                                  f"       expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"      exception: {type(e)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break

    if result:
        base = ThemeArray([ThemeStr("Hello World", ThemeAttr("types", "emphasis"))], False)
        testdata: tuple[Any, ...] = (
            (ThemeRef("separators", "matchbullet", True),
             "ThemeArray([ThemeStr('Hello World', ThemeAttr('types', 'emphasis'), False), "
             "ThemeRef('separators', 'matchbullet', True)])", None),
            (None,
             None, ProgrammingError),
        )
        for indata, expected_result, expected_exception in testdata:
            try:
                tmp = copy.deepcopy(base)
                tmp.append(indata)
                if expected_exception is None:
                    if repr(tmp) != expected_result:
                        message = f"{fun.__name__}.append() did not yield expected result:\n" \
                                  f"          input: {repr(base)}\n" \
                                  f"         append: {repr(indata)}\n" \
                                  f"         output: {repr(tmp)}\n" \
                                  f"       expected: {expected_result}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}.append() did not yield expected result:\n" \
                              f"          input: {repr(base)}\n" \
                              f"         append: {repr(indata)}\n" \
                              f"         output: {repr(tmp)}\n" \
                              f"       expected: {expected_exception}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"          input: {repr(base)}\n" \
                                  f"         append: {indata}\n" \
                                  f"      exception: {type(e)}\n" \
                                  f"       expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {base}\n" \
                              f"         append: {indata}\n" \
                              f"      exception: {type(e)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break

    if result:
        base = ThemeArray([ThemeStr("Hello ", ThemeAttr("types", "emphasis"))], False)
        testdata: tuple[Any, ...] = (
            (ThemeArray([ThemeStr("World", ThemeAttr("types", "generic"))], False),
             "ThemeArray([ThemeStr('Hello ', ThemeAttr('types', 'emphasis'), False), "
             "ThemeStr('World', ThemeAttr('types', 'generic'), False)])", None),
            ([ThemeStr("World", ThemeAttr("types", "generic"), False)],
             "ThemeArray([ThemeStr('Hello ', ThemeAttr('types', 'emphasis'), False), "
             "ThemeStr('World', ThemeAttr('types', 'generic'), False)])", None),
            (None,
             None, ProgrammingError),
        )
        for indata, expected_result, expected_exception in testdata:
            try:
                tmp = copy.deepcopy(base)
                tmp += indata
                if expected_exception is None:
                    if repr(tmp) != expected_result:
                        message = f"{fun.__name__}.__add__() did not yield expected result:\n" \
                                  f"          input: {repr(base)}\n" \
                                  f"         append: {repr(indata)}\n" \
                                  f"         output: {repr(tmp)}\n" \
                                  f"       expected: {expected_result}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}.__add__() did not yield expected result:\n" \
                              f"          input: {repr(base)}\n" \
                              f"         append: {repr(indata)}\n" \
                              f"         output: {repr(tmp)}\n" \
                              f"       expected: {expected_exception}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}.__add__() did not yield expected result:\n" \
                                  f"          input: {repr(base)}\n" \
                                  f"         append: {indata}\n" \
                                  f"      exception: {type(e)}\n" \
                                  f"       expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}.__add__() did not yield expected result:\n" \
                              f"          input: {base}\n" \
                              f"         append: {indata}\n" \
                              f"      exception: {type(e)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break

    if result:
        indata = ThemeArray([ThemeStr("Hello ", ThemeAttr("types", "generic")),
                             ThemeStr("World", ThemeAttr("types", "emphasis"))])
        tmp = str(indata)
        if tmp != "Hello World":
            message = f"{fun.__name__}.__str__() did not yield expected result:\n" \
                      f"          input: {repr(indata)}\n" \
                      f"         output: {tmp}\n" \
                      f"       expected: Hello World"
            result = False

    if result:
        testdata: tuple[Any, ...] = (
            (ThemeArray([ThemeStr("12345", ThemeAttr("types", "generic"))], False),
             5, None),
            (ThemeArray([ThemeStr("", ThemeAttr("types", "generic"), False)]),
             0, None),
            # "–"; this needs to be modified if the separator changes, so don't!
            (ThemeArray([ThemeRef("separators", "range", False)]),
             1, None),
        )
        for indata, expected_result, expected_exception in testdata:
            try:
                tmp = len(indata)
                if expected_exception is None:
                    if tmp != expected_result:
                        message = f"{fun.__name__}.__len__() did not yield expected result:\n" \
                                  f"          input: {repr(indata)}\n" \
                                  f"         output: {repr(tmp)}\n" \
                                  f"       expected: {expected_result}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}.__len__() did not yield expected result:\n" \
                              f"          input: {repr(indata)}\n" \
                              f"         output: {repr(tmp)}\n" \
                              f"       expected: {expected_exception}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}.__len__() did not yield expected result:\n" \
                                  f"          input: {repr(indata)}\n" \
                                  f"      exception: {type(e)}\n" \
                                  f"       expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}.__len__() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"      exception: {type(e)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break

    if result:
        testdata: tuple[Any, ...] = (
            (ThemeArray([ThemeStr("A", ThemeAttr("types", "generic"))], False),
             ThemeArray([ThemeStr("A", ThemeAttr("types", "generic"))], False),
             True, None),
            (ThemeArray([ThemeStr("A", ThemeAttr("types", "generic"))], False),
             ThemeArray([ThemeStr("B", ThemeAttr("types", "generic"))], False),
             False, None),
            (ThemeArray([ThemeStr("A", ThemeAttr("types", "generic"))], False),
             "3",
             False, None),
        )
        for indata1, indata2, expected_result, expected_exception in testdata:
            try:
                tmp = indata1 == indata2
                if expected_exception is None:
                    if tmp != expected_result:
                        message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                                  f"         input1: {repr(indata1)}\n" \
                                  f"         input2: {repr(indata2)}\n" \
                                  f"         output: {repr(tmp)}\n" \
                                  f"       expected: {expected_result}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                              f"         input1: {repr(indata1)}\n" \
                              f"         input2: {repr(indata2)}\n" \
                              f"         output: {repr(tmp)}\n" \
                              f"       expected: {expected_exception}"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                                  f"         input1: {repr(indata1)}\n" \
                                  f"         input2: {repr(indata2)}\n" \
                                  f"      exception: {type(e)}\n" \
                                  f"       expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}.__eq__() did not yield expected result:\n" \
                              f"         input1: {repr(indata1)}\n" \
                              f"         input2: {repr(indata2)}\n" \
                              f"      exception: {type(e)}\n" \
                              f"       expected: {expected_result}"
                    result = False
                    break

    return message, result


def test_themearray_detab(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.themearray_detab

    if result:
        # Indata format:
        # (ThemeArray, expected_result, expected_exception)
        testdata: tuple = (
            # ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("Foo	Bar", ThemeAttr("types", "generic"), selected=False)],
                # expected_result
                [ThemeStr("Foo   Bar", ThemeAttr("types", "generic"), selected=False)],
                # expected_exception
                None,
            ),
            # ThemeArray as list of ThemeStr; no tabs.
            (
                # themearray
                [ThemeStr("Foo", ThemeAttr("types", "generic"), selected=False)],
                # expected_result
                [ThemeStr("Foo", ThemeAttr("types", "generic"), selected=False)],
                # expected_exception
                None,
            ),
            # ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("Foo		Bar", ThemeAttr("types", "generic"), selected=False)],
                # expected_result
                [ThemeStr("Foo         Bar", ThemeAttr("types", "generic"), selected=False)],
                # expected_exception
                None,
            ),
            # ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("     Foo	Bar", ThemeAttr("types", "generic"), selected=False)],
                # expected_result
                [ThemeStr("     Foo        Bar", ThemeAttr("types", "generic"), selected=False)],
                # expected_exception
                None,
            ),
            # ThemeArray as list of ThemeRef.
            (
                # themearray
                [ThemeRef("strings", "none", selected=False)],
                # expected_result
                [ThemeRef("strings", "none", selected=False)],
                # expected_exception
                None,
            ),
            # ThemeArray with weird contents.
            (
                # themearray
                ["string"],
                # expected_result
                [],
                # expected_exception
                None,
            ),
        )

        for themearray, expected_result, expected_exception in testdata:
            try:
                tmp = fun(themearray)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
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
                                  f"       themearray: {themearray}\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"        exception: {type(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_themearray_flatten(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.themearray_flatten

    if result:
        # Indata format:
        # (ThemeArray, expected_result, expected_exception)
        testdata: tuple = (
            # ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                None,
            ),
            # ThemeArray as list of ThemeRef.
            (
                # themearray
                [ThemeRef("strings", "none")],
                [ThemeStr("<none>", ThemeAttr("types", "none"))],
                None,
            ),
            # ThemeArray as list of non-valid types.
            (
                # themearray
                ["string"],
                None,
                ProgrammingError,
            ),
        )

        for themearray, expected_result, expected_exception in testdata:
            try:
                tmp = fun(themearray)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
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
                                  f"       themearray: {themearray}\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"        exception: {type(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_themearray_select(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.themearray_select

    if result:
        # Indata format:
        # (ThemeArray, select, expected_result, expected_exception)
        testdata: tuple = (
            # Selected=None ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=None)],
                # selected
                True,
                # force
                False,
                # expected_result
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=True)],
                # expected_exception
                None,
            ),
            # Selected=None ThemeArray as list of ThemeRef.
            (
                # themearray
                [ThemeRef("strings", "none", selected=None)],
                # selected
                True,
                # force
                False,
                # expected_result
                [ThemeRef("strings", "none", selected=True)],
                # expected_exception
                None,
            ),
            # Selected=None ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=None)],
                # selected
                False,
                # force
                False,
                # expected_result
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=False)],
                # expected_exception
                None,
            ),
            # Selected=None ThemeArray as list of ThemeRef.
            (
                # themearray
                [ThemeRef("strings", "none", selected=None)],
                # selected
                False,
                # force
                False,
                # expected_result
                [ThemeRef("strings", "none", selected=False)],
                # expected_exception
                None,
            ),
            # Not selected ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=False)],
                # selected
                True,
                # force
                False,
                # expected_result
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=False)],
                # expected_exception
                None,
            ),
            # Not selected ThemeArray as list of ThemeRef.
            (
                # themearray
                [ThemeRef("strings", "none", selected=False)],
                # selected
                True,
                # force
                False,
                # expected_result
                [ThemeRef("strings", "none", selected=False)],
                # expected_exception
                None,
            ),
            # Selected ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=True)],
                # selected
                False,
                # force
                False,
                # expected_result
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=True)],
                # expected_exception
                None,
            ),
            # Selected ThemeArray as list of ThemeRef.
            (
                # themearray
                [ThemeRef("strings", "none", selected=True)],
                # selected
                False,
                # force
                False,
                # expected_result
                [ThemeRef("strings", "none", selected=True)],
                # expected_exception
                None,
            ),
            # Not selected ThemeArray as list of ThemeStr; force.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=False)],
                # selected
                True,
                # force
                True,
                # expected_result
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=True)],
                # expected_exception
                None,
            ),
            # Not selected ThemeArray as list of ThemeRef; force.
            (
                # themearray
                [ThemeRef("strings", "none", selected=False)],
                # selected
                True,
                # force
                True,
                # expected_result
                [ThemeRef("strings", "none", selected=True)],
                # expected_exception
                None,
            ),
            # Selected ThemeArray as list of ThemeStr; force.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=True)],
                # selected
                False,
                # force
                True,
                # expected_result
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"), selected=False)],
                # expected_exception
                None,
            ),
            # Selected ThemeArray as list of ThemeRef; force.
            (
                # themearray
                [ThemeRef("strings", "none", selected=True)],
                # selected
                False,
                # force
                True,
                # expected_result
                [ThemeRef("strings", "none", selected=False)],
                # expected_exception
                None,
            ),
            # ThemeArray as list of non-valid types.
            (
                # themearray
                ["string"],
                # selected,
                True,
                # force
                False,
                None,
                ProgrammingError,
            ),
        )

        for themearray, selected, force, expected_result, expected_exception in testdata:
            try:
                tmp = fun(themearray, selected=selected, force=force)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"         selected: {selected}\n" \
                              f"            force: {force}\n" \
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
                                  f"       themearray: {themearray}\n" \
                                  f"         selected: {selected}\n" \
                                  f"            force: {force}\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"         selected: {selected}\n" \
                              f"            force: {force}\n" \
                              f"        exception: {type(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_themearray_split(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.themearray_split

    if result:
        # Indata format:
        # (ThemeArray, select, expected_result, expected_exception)
        testdata: tuple = (
            # ThemeArray as list of ThemeStr, " " as separator.
            (
                # themearray
                [ThemeStr("Foo Bar", ThemeAttr("types", "generic"), selected=False)],
                # separator
                " ",
                # expected_result
                [[ThemeStr("F", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("o", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("o", ThemeAttr("types", "generic"), selected=False)],
                 [ThemeStr("B", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("a", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("r", ThemeAttr("types", "generic"), selected=False)]],
                # expected_exception
                None,
            ),
            # ThemeArray as list of ThemeStr, ":" as separator.
            (
                # themearray
                [ThemeStr("Foo Bar", ThemeAttr("types", "generic"), selected=False)],
                # separator
                ":",
                # expected_result
                [[ThemeStr("F", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("o", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("o", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr(" ", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("B", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("a", ThemeAttr("types", "generic"), selected=False),
                  ThemeStr("r", ThemeAttr("types", "generic"), selected=False)]],
                # expected_exception
                None,
            ),
            # Empty ThemeArray as list of ThemeStr, " " as separator.
            (
                # themearray
                [],
                # separator
                " ",
                # expected_result
                [],
                # expected_exception
                None,
            ),
        )

        for themearray, separator, expected_result, expected_exception in testdata:
            try:
                tmp = fun(themearray, separator=separator)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"        separator: '{separator}'\n" \
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
                                  f"       themearray: {themearray}\n" \
                                  f"        separator: '{separator}'\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"        separator: '{separator}'\n" \
                              f"        exception: {type(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_themestring_to_cursestuple(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.themestring_to_cursestuple

    if result:
        # Indata format:
        # (ThemeArray, select, expected_result, expected_exception)
        testdata: tuple = (
            # ThemeStr (selected=False); selected=False.
            (
                # themearray
                ThemeStr("Foo Bar", ThemeAttr("types", "generic"), selected=False),
                # selected
                False,
                # expected_result
                ("Foo Bar", 768),
                # expected_exception
                None,
            ),
            # ThemeStr (selected=True); selected=False.
            (
                # themearray
                ThemeStr("Foo Bar", ThemeAttr("types", "generic"), selected=False),
                # selected
                False,
                # expected_result
                ("Foo Bar", 768),
                # expected_exception
                None,
            ),
            # ThemeStr (selected=None); selected=None.
            (
                # themearray
                ThemeStr("Foo Bar", ThemeAttr("types", "generic"), selected=None),
                # selected
                None,
                # expected_result
                ("Foo Bar", 768),
                # expected_exception
                None,
            ),
        )

        for themearray, selected, expected_result, expected_exception in testdata:
            try:
                curses.initscr()
                curses.start_color()
                curses_helper.read_theme(DEFAULT_THEME_FILE, DEFAULT_THEME_FILE)
                curses_helper.themefile = None
                curses_helper.init_curses()
                tmp = fun(themearray, selected=selected)
                curses.endwin()
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"         selected: {selected}\n" \
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
                                  f"       themearray: {themearray}\n" \
                                  f"         selected: {selected}\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"         selected: {selected}\n" \
                              f"        exception: {type(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    try:
        curses.endwin()
    except curses.error:
        pass
    return message, result


def test_themearray_to_string(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.themearray_to_string

    if result:
        # Indata format:
        # (ThemeArray, expected_result, expected_exception)
        testdata: tuple = (
            # ThemeArray.
            (
                # themearray
                ThemeArray([ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))]),
                "Foo Bar Baz",
                None,
            ),
            # ThemeArray as list of ThemeStr.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                "Foo Bar Baz",
                None,
            ),
        )

        for themearray, expected_result, expected_exception in testdata:
            try:
                tmp = fun(themearray)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
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
                                  f"       themearray: {themearray}\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"        exception: {type(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_themearray_truncate(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.themearray_truncate

    if result:
        # Indata format:
        # (ThemeArray, max_len, expected_result, expected_exception)
        testdata: tuple = (
            # ThemeArray; len(themearray) > max_len.
            (
                # themearray
                ThemeArray([ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))]),
                # max_len
                len("Foo Bar"),
                [ThemeStr("Foo Bar", ThemeAttr("types", "generic"))],
                None,
            ),
            # ThemeArray as list of ThemeStr; len(themearray) > max_len.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                # max_len
                len("Foo Bar"),
                [ThemeStr("Foo Bar", ThemeAttr("types", "generic"))],
                None,
            ),
            # ThemeArray as list of ThemeStr; len(themearray) == max_len.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                # max_len
                len("Foo Bar Baz"),
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                None,
            ),
            # ThemeArray as list of ThemeStr; len(themearray) < max_len.
            (
                # themearray
                [ThemeStr("Foo Bar", ThemeAttr("types", "generic"))],
                # max_len
                len("Foo Bar Baz"),
                [ThemeStr("Foo Bar", ThemeAttr("types", "generic"))],
                None,
            ),
        )

        for themearray, max_len, expected_result, expected_exception in testdata:
            try:
                tmp = fun(themearray, max_len)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"          max_len: {max_len}\n" \
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
                                  f"       themearray: {themearray}\n" \
                                  f"          max_len: {max_len}\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"          max_len: {max_len}\n" \
                              f"        exception: {type(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_themearray_wrap_line(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.themearray_wrap_line

    if result:
        # Indata format:
        # (ThemeArray, maxwidth, wrap_marker, expected_result, expected_exception)
        testdata: tuple = (
            # ThemeArray as list, maxwidth > len(themearray), wrap_marker.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                # maxwidth
                len("Foo Bar Baz") + 1,
                # wrap_marker
                True,
                [[ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))]],
                None,
            ),
            # ThemeArray as list, maxwidth == len(themearray), wrap_marker.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                # maxwidth
                len("Foo Bar Baz"),
                # wrap_marker
                True,
                [[ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))]],
                None,
            ),
            # ThemeArray as list, maxwidth < len(themearray), wrap_marker.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                # maxwidth
                len("Foo Bar Baz") - 1,
                # wrap_marker
                True,
                [[ThemeStr("Foo Bar B", ThemeAttr("types", "generic")),
                  ThemeStr("⏎", ThemeAttr("types", "separator_line_break"), False)],
                 [ThemeStr("az", ThemeAttr("types", "generic"))]],
                None,
            ),
            # ThemeArray as list, maxwidth < len(themearray), no wrap_marker.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                # maxwidth
                len("Foo Bar Baz") - 1,
                # wrap_marker
                False,
                [[ThemeStr("Foo Bar Ba", ThemeAttr("types", "generic"))],
                 [ThemeStr("z", ThemeAttr("types", "generic"))]],
                None,
            ),
            # Empty ThemeArray, maxwidth > len(themearray), wrap_marker.
            (
                # themearray
                [],
                # maxwidth
                len("Foo Bar Baz") + 1,
                # wrap_marker
                True,
                [],
                None,
            ),
            # ThemeArray as list, maxwidth == -1, wrap_marker.
            (
                # themearray
                [ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))],
                # maxwidth
                -1,
                # wrap_marker
                True,
                [[ThemeStr("Foo Bar Baz", ThemeAttr("types", "generic"))]],
                None,
            ),
        )

        for themearray, maxwidth, wrap_marker, expected_result, expected_exception in testdata:
            try:
                tmp = fun(themearray, maxwidth=maxwidth, wrap_marker=wrap_marker)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"         maxwidth: {maxwidth}\n" \
                              f"      wrap_marker: {wrap_marker}\n" \
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
                                  f"       themearray: {themearray}\n" \
                                  f"         maxwidth: {maxwidth}\n" \
                                  f"      wrap_marker: {wrap_marker}\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"       themearray: {themearray}\n" \
                              f"         maxwidth: {maxwidth}\n" \
                              f"      wrap_marker: {wrap_marker}\n" \
                              f"        exception: {type(e)}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_format_helptext(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.format_helptext

    if result:
        # Indata format:
        # (helptext, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            ([("[F1] / [Shift] + H", "Show this helptext"), ("[Ctrl] + X", "Exit program")],
             [{"lineattrs": WidgetLineAttrs.NORMAL,
               "columns": [[ThemeStr("[F1] / [Shift] + H", ThemeAttr("windowwidget", "highlight"))],
                           [ThemeStr("Show this helptext", ThemeAttr("windowwidget", "default"))]],
               "retval": None},
              {"lineattrs": WidgetLineAttrs.NORMAL,
               "columns": [[ThemeStr("[Ctrl] + X", ThemeAttr("windowwidget", "highlight"))],
                           [ThemeStr("Exit program", ThemeAttr("windowwidget", "default"))]],
               "retval": None}], None),
        )
        for indata in testdata:
            helptext, expected_result, expected_exception = indata
            try:
                tmp = fun(helptext)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {helptext}\n" \
                              f"         result: {tmp}\n" \
                              f"       expected: {expected_result}\n"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"          input: {helptext}\n" \
                                  f"      exception: {e}\n" \
                                  f"       expected: {expected_exception}\n"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {helptext}\n" \
                              f"      exception: {e}\n" \
                              f"       expected: {expected_result}\n"
                    result = False
                    break
    return message, result


def test_set_mousemask(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    curses.initscr()
    fun = curses_helper.set_mousemask

    if result:
        # Indata format:
        # (mask, expected_exception)
        testdata: tuple[Any, ...] = (
            (-1, None),
            (0, None),
        )
        for indata, expected_exception in testdata:
            try:
                fun(indata)
            except Exception as e:
                if isinstance(e, expected_exception):
                    pass
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"      exception: {e}\n" \
                              f"       expected: {expected_exception}\n"
                    result = False
                    break
    curses.endwin()
    return message, result


def test_get_mousemask(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.get_mousemask

    if result:
        # Indata format:
        # (mask, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            (-1, -1, None),
            (0, 0, None),
        )
        for indata, expected_result, expected_exception in testdata:
            try:
                curses_helper.set_mousemask(indata)
                if (tmp := fun()) != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"         result: {tmp}\n" \
                              f"       expected: {expected_result}\n"
                    result = False
                    break
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"          input: {indata}\n" \
                                  f"      exception: {e}\n" \
                                  f"       expected: {expected_exception}\n"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"          input: {indata}\n" \
                              f"      exception: {e}\n" \
                              f"       expected: {expected_result}\n"
                    result = False
                    break
    return message, result


def test_read_theme(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.read_theme

    if result:
        # Indata format:
        # (configthemefile, defaultthemefile, expected_exception)
        testdata: tuple[Any, ...] = (
            (os.path.join(THEMES_DIR, "cvd.yaml"), DEFAULT_THEME_FILE, None),
            (os.path.join(THEMES_DIR, "cvd"), DEFAULT_THEME_FILE, None),
            (os.path.join(THEMES_DIR, "NonExistingTheme"), DEFAULT_THEME_FILE, None),
            (os.path.join(THEMES_DIR, "NonExistingTheme"), None, ProgrammingError),
            (None, DEFAULT_THEME_FILE, None),
            (None, os.path.join(THEMES_DIR, "NonExistingTheme"), ProgrammingError),
            (None, None, ProgrammingError),
        )
        for configthemefile, defaultthemefile, expected_exception in testdata:
            try:
                curses_helper.themefile = None
                fun(configthemefile, defaultthemefile)
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f" configthemefile: {configthemefile}\n" \
                                  f"defaultthemefile: {defaultthemefile}\n" \
                                  f"       exception: {e}\n" \
                                  f"        expected: {expected_exception}\n"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f" configthemefile: {configthemefile}\n" \
                              f"defaultthemefile: {defaultthemefile}\n" \
                              f"       exception: {e}\n"
                    result = False
                    break
    return message, result


def test_get_theme_ref(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.get_theme_ref

    curses_helper.read_theme(DEFAULT_THEME_FILE, DEFAULT_THEME_FILE)

    if result:
        tmp = fun()
        if tmp != curses_helper.themestr.ThemeStrConfiguration.theme:
            message = f"{fun.__name__}() did not yield expected result:\n" \
                      f"        expected: {curses_helper.themestr.ThemeStrConfiguration.theme}\n" \
                      f"             got: {tmp}\n"
            result = False
    return message, result


def test_init_curses(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.init_curses

    if result:
        # Indata format:
        # (configthemefile, defaultthemefile, expected_exception)
        testdata: tuple[Any, ...] = (
            (os.path.join(TEST_DIR, "fg_equals_bg.yaml"), ValueError),
            (os.path.join(TEST_DIR, "colorremap.yaml"), None),
            (os.path.join(TEST_DIR, "attr_not_known.yaml"), None),
            (os.path.join(TEST_DIR, "attr_not_str.yaml"), None),
            (os.path.join(TEST_DIR, "col_not_known.yaml"), ValueError),
            (os.path.join(TEST_DIR, "col_not_str.yaml"), ValueError),
            # This is just to restore things to a sensible state
            (DEFAULT_THEME_FILE, None),
        )
        for configthemefile, expected_exception in testdata:
            try:
                curses.initscr()
                curses.start_color()
                curses_helper.read_theme(configthemefile, DEFAULT_THEME_FILE)
                curses_helper.themefile = None
                fun()
                curses.endwin()
            except Exception as e:
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        pass
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f" configthemefile: {configthemefile}\n" \
                                  f"       exception: {e}\n" \
                                  f"        expected: {expected_exception}\n"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f" configthemefile: {configthemefile}\n" \
                              f"       exception: {e}\n"
                    result = False
                    break
    try:
        curses.endwin()
    except curses.error:
        pass
    return message, result


def test_color_log_severity(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.color_log_severity

    if result:
        # Indata format:
        # (obj, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # Valid
            (
                LogLevel.EMERG,
                ThemeAttr("logview", "severity_emergency"),
                None,
            ),
            # Valid
            (
                LogLevel.ALL,
                ThemeAttr("logview", "severity_debug"),
                None,
            ),
            # Out of range negative
            (
                LogLevel.EMERG - 1,
                ThemeAttr("logview", "severity_info"),
                None,
            ),
            # Out of range positive
            (
                LogLevel.ALL + 1,
                ThemeAttr("logview", "severity_info"),
                None,
            ),
        )

        for obj, expected_result, expected_exception in testdata:
            try:
                tmp = fun(obj)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_color_status_group(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.color_status_group

    if result:
        # Indata format:
        # (obj, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # Valid
            (
                StatusGroup.CRIT,
                ThemeAttr("main", "status_critical"),
                None,
            ),
            # Valid
            (
                StatusGroup.DONE,
                ThemeAttr("main", "status_done"),
                None,
            ),
            # Out of range negative
            (
                StatusGroup.CRIT - 1,
                ThemeAttr("main", "status_unknown"),
                None,
            ),
            # Out of range positive
            (
                StatusGroup.DONE + 1,
                ThemeAttr("main", "status_unknown"),
                None,
            ),
        )

        for obj, expected_result, expected_exception in testdata:
            try:
                tmp = fun(obj)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_window_tee_hline(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.window_tee_hline
    win = curses.initscr()

    if result:
        # Indata format:
        # (y-position, start, end, formatting, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # Without custom formatting
            (
                0, 0, 5, None,
                None,
                None,
            ),
            # With custom formatting
            (
                0, 0, 5, ThemeAttr("logo", "bright"),
                None,
                None,
            ),
        )

        for ypos, start, end, formatting, expected_result, expected_exception in testdata:
            try:
                tmp = fun(win, ypos, start, end, formatting)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    curses.endwin()
    return message, result


def test_window_tee_vline(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.window_tee_vline
    win = curses.initscr()

    if result:
        # Indata format:
        # (x-position, start, end, formatting, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # Without custom formatting
            (
                0, 0, 5, None,
                None,
                None,
            ),
            # With custom formatting
            (
                0, 0, 5, ThemeAttr("logo", "bright"),
                None,
                None,
            ),
        )

        for xpos, start, end, formatting, expected_result, expected_exception in testdata:
            try:
                tmp = fun(win, xpos, start, end, formatting)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    curses.endwin()
    return message, result


def test_scrollbar_vertical(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.scrollbar_vertical
    win = curses.initscr()

    if result:
        # Indata format:
        # (x-position, miny, maxy, height, yoffset, clear_color,
        #  expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # Does not fit in visible area
            (
                0, 0, 10, 30, 5, ThemeAttr("windowwidget", "boxdrawing"),
                ((0, 0), (10, 0), (3, 0, 3)),
                None,
            ),
            # Fits in visible area
            (
                0, 0, 10, 5, 0, ThemeAttr("windowwidget", "boxdrawing"),
                ((-1, -1), (-1, -1), (-1, -1, -1)),
                None,
            ),
        )

        for xpos, miny, maxy, height, yoffset, clear_color, \
                expected_result, expected_exception in testdata:
            try:
                tmp = fun(win, xpos, miny, maxy, height, yoffset, clear_color)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    curses.endwin()
    return message, result


def test_scrollbar_horizontal(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.scrollbar_horizontal
    win = curses.initscr()

    if result:
        # Indata format:
        # (y-position, minx, maxx, width, xoffset, clear_color,
        #  expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # Does not fit in visible area
            (
                0, 0, 10, 30, 5, ThemeAttr("windowwidget", "boxdrawing"),
                ((0, 0), (0, 10), (0, 3, 5)),
                None,
            ),
            # Fits in visible area
            (
                0, 0, 10, 5, 0, ThemeAttr("windowwidget", "boxdrawing"),
                ((-1, -1), (-1, -1), (-1, -1, -1)),
                None,
            ),
        )

        for ypos, minx, maxx, width, xoffset, clear_color, \
                expected_result, expected_exception in testdata:
            try:
                tmp = fun(win, ypos, minx, maxx, width, xoffset, clear_color)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    curses.endwin()
    return message, result


def test_generate_heatmap(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.generate_heatmap
    _win = curses.initscr()

    if result:
        # Indata format:
        # (maxwidth, stgroups, selected, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # Repeat statusgroups, should be compacted
            (
                20, [StatusGroup.OK, StatusGroup.OK, StatusGroup.OK, StatusGroup.OK,
                     StatusGroup.ADMIN, StatusGroup.PENDING, StatusGroup.OK], 0,
                [[ThemeStr('█', ThemeAttr('main', 'status_ok'), True),
                  ThemeStr('■■■', ThemeAttr('main', 'status_ok'), False),
                  ThemeStr('■', ThemeAttr('main', 'status_admin'), False),
                  ThemeStr('■', ThemeAttr('main', 'status_pending'), False),
                  ThemeStr('■', ThemeAttr('main', 'status_ok'), False)]],
                None,
            ),
            # No stgroups
            (
                20, [], 0,
                [],
                None,
            ),
        )

        for maxwidth, stgroups, selected, \
                expected_result, expected_exception in testdata:
            try:
                tmp = fun(maxwidth, stgroups, selected)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    curses.endwin()
    return message, result


def test_percentagebar(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.percentagebar
    _win = curses.initscr()

    if result:
        # Indata format:
        # (minx, maxx, total, subsets, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # A valid percentage bar with width
            (
                0, 20, 100, [
                    (30, ThemeRef("strings", "cputime_user")),
                    (50, ThemeRef("strings", "cputime_total_system")),
                    (20, ThemeRef("strings", "cputime_total_guest")),
                ],
                [ThemeStr('■■■■■■', ThemeAttr('types', 'cputime_user'), False),
                 ThemeStr('■■■■■■■■■■', ThemeAttr('types', 'cputime_total_system'), False),
                 ThemeStr('■■■■', ThemeAttr('types', 'cputime_total_guest'), False),
                 ThemeStr(' ', ThemeAttr('types', 'generic'), False)],
                None,
            ),
            # A percentage bar with no total
            (
                0, 20, 0, [
                    (30, ThemeRef("strings", "cputime_user")),
                    (50, ThemeRef("strings", "cputime_total_system")),
                    (20, ThemeRef("strings", "cputime_total_guest")),
                ],
                [ThemeStr('                     ', ThemeAttr('types', 'generic'), False)],
                None,
            ),
        )

        for minx, maxx, total, subsets, \
                expected_result, expected_exception in testdata:
            try:
                tmp = fun(minx, maxx, total, subsets)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    curses.endwin()
    return message, result


def test_get_labels(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.get_labels

    if result:
        # Indata format:
        # (labels, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # A valid set of labels
            (
                {
                    "k8s-app": "kube-dns",
                },
                [
                    {
                        "lineattrs": WidgetLineAttrs.NORMAL,
                        "columns": [[ThemeStr("k8s-app", ThemeAttr("windowwidget", "default"))],
                                    [ThemeStr("kube-dns",
                                              ThemeAttr("windowwidget", "highlight"))]],
                        "retval": None,
                    },
                ],
                None,
            ),
            # No labels
            (
                None,
                None,
                None,
            ),
        )

        for labels, expected_result, expected_exception in testdata:
            try:
                tmp = fun(labels)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


def test_map_key(verbose: bool = False) -> tuple[str, bool]:
    message = ""
    result = True

    fun = curses_helper.map_key

    if result:
        # Indata format:
        # (labels, expected_result, expected_exception)
        testdata: tuple[Any, ...] = (
            # No callable defined; using Enter is OK
            ("fake1.yaml", "test1", None, "enter", "",
             ([curses.KEY_ENTER, 10, 13], "[Enter]"), None),
            # Callable defined; using Enter is not acceptable
            ("fake1.yaml", "test1", test_map_key, "enter", "",
             None, Exception),
            ("fake1.yaml", "test1", None, "f1", "",
             ([curses.KEY_F1], "[F1]"), None),
            ("fake1.yaml", "test1", None, "f1", "shift",
             ([curses.KEY_F13], "[Shift] + [F1] / [F13]"), None),
            ("fake1.yaml", "test1", None, "f13", "",
             ([curses.KEY_F13], "[Shift] + [F1] / [F13]"), None),
            # Unsupported modifier for F-key
            ("fake1.yaml", "test1", None, "f1", "ctrl",
             None, Exception),
            ("fake1.yaml", "test1", None, "a", "",
             ([ord("a")], "A"), None),
            ("fake1.yaml", "test1", None, "a", "shift",
             ([ord("A")], "[Shift] + A"), None),
            ("fake1.yaml", "test1", None, "a", "ctrl",
             ([ord("a") - 96], "[Ctrl] + A"), None),
            # Unsupported modifier
            ("fake1.yaml", "test1", None, "a", "alt",
             None, Exception),
            # Invalid key
            ("fake1.yaml", "test1", None, "ab", "",
             None, Exception),
        )

        for view_file, shortcut, activatedfun, key, modifier, \
                expected_result, expected_exception in testdata:
            try:
                with mock.patch("sys.exit", side_effect=Exception()):
                    tmp = fun(view_file, shortcut, activatedfun, key, modifier)
                if tmp != expected_result:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"           result: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
            except Exception as e:
                tmp = str(e)
                if expected_exception is not None:
                    if isinstance(e, expected_exception):
                        if not expected_result or expected_result == tmp:
                            continue
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"           result: {tmp}\n" \
                                  f"  expected result: {expected_result}"
                        result = False
                        break
                    else:
                        message = f"{fun.__name__}() did not yield expected result:\n" \
                                  f"        exception: {type(e)}\n" \
                                  f"          message: {tmp}\n" \
                                  f"         expected: {expected_exception}"
                        result = False
                        break
                else:
                    message = f"{fun.__name__}() did not yield expected result:\n" \
                              f"        exception: {type(e)}\n" \
                              f"          message: {tmp}\n" \
                              f"  expected result: {expected_result}"
                    result = False
                    break
    return message, result


tests: dict[tuple[str, ...], dict[str, Any]] = {
    ("ThemeStr()",): {
        "callable": test_themestring,
        "result": None,
    },
    ("ThemeRef()",): {
        "callable": test_themeref,
        "result": None,
    },
    ("ThemeArray()",): {
        "callable": test_themearray,
        "result": None,
    },
    ("themearray_detab()",): {
        "callable": test_themearray_detab,
        "result": None,
    },
    ("themearray_flatten()",): {
        "callable": test_themearray_flatten,
        "result": None,
    },
    ("themearray_select()",): {
        "callable": test_themearray_select,
        "result": None,
    },
    ("themearray_split()",): {
        "callable": test_themearray_split,
        "result": None,
    },
    ("themestring_to_cursestuple()",): {
        "callable": test_themestring_to_cursestuple,
        "result": None,
    },
    ("themearray_to_string()",): {
        "callable": test_themearray_to_string,
        "result": None,
    },
    ("themearray_truncate()",): {
        "callable": test_themearray_truncate,
        "result": None,
    },
    ("themearray_wrap_line()",): {
        "callable": test_themearray_wrap_line,
        "result": None,
    },
    ("format_helptext()",): {
        "callable": test_format_helptext,
        "result": None,
    },
    ("set_mousemask()",): {
        "callable": test_set_mousemask,
        "result": None,
    },
    ("get_mousemask()",): {
        "callable": test_get_mousemask,
        "result": None,
    },
    ("read_theme()",): {
        "callable": test_read_theme,
        "result": None,
    },
    ("get_theme_ref()",): {
        "callable": test_get_theme_ref,
        "result": None,
    },
    ("init_curses()",): {
        "callable": test_init_curses,
        "result": None,
    },
    ("color_log_severity()",): {
        "callable": test_color_log_severity,
        "result": None,
    },
    ("color_status_group()",): {
        "callable": test_color_status_group,
        "result": None,
    },
    ("window_tee_hline()",): {
        "callable": test_window_tee_hline,
        "result": None,
    },
    ("window_tee_vline()",): {
        "callable": test_window_tee_vline,
        "result": None,
    },
    ("scrollbar_vertical()",): {
        "callable": test_scrollbar_vertical,
        "result": None,
    },
    ("scrollbar_horizontal()",): {
        "callable": test_scrollbar_horizontal,
        "result": None,
    },
    ("generate_heatmap()",): {
        "callable": test_generate_heatmap,
        "result": None,
    },
    ("percentagebar()",): {
        "callable": test_percentagebar,
        "result": None,
    },
    ("get_labels()",): {
        "callable": test_get_labels,
        "result": None,
    },
    ("map_key()",): {
        "callable": test_map_key,
        "result": None,
    },
}


def main() -> int:
    global tests

    fail = 0
    success = 0
    verbose = False
    failed_testcases = []

    init_ansithemeprint(themefile=None)
    cmtlib.cmtconfig = cmtlib.read_cmtconfig()

    defaultthemefile = DEFAULT_THEME_FILE
    tmpthemefile = deep_get(cmtlib.cmtconfig, DictPath("Global#theme"))
    themefile, _theme_path_found = \
        expand_path(path=tmpthemefile, search_paths=[os.getcwd(), THEMES_DIR],
                    suffixes=[".yaml"], fallback=defaultthemefile)
    curses_helper.read_theme(themefile, defaultthemefile)

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
