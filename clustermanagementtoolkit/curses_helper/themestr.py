# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Classes for ThemeAttr/ThemeRef/ThemeStr/ThemeArray.
"""

from typing import ClassVar, NamedTuple, Union

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-few-public-methods
class ThemeStrConfiguration:
    """
    TheneStr/ThemeArray-related configuration.
    """
    theme: ClassVar[dict] = {}
    themefile: FilePath | None = None
    color: ClassVar[dict[str, tuple[int, int]]] = {}
    pairs: ClassVar[dict[tuple[int, int], int]] = {}


# A reference to text formatting
class ThemeAttr(NamedTuple):
    """
    A reference to formatting for a themed string.

        Parameters:
            context: The context to use when doing a looking in themes
            key: The key to use when doing a looking in themes
    """
    context: str
    key: str

    def __repr__(self) -> str:
        return f"ThemeAttr('{self.context}', '{self.key}')"


class ThemeStr:
    """
    A themed string for use with curses.

        Parameters:
            string: A string
            themeattr: The themeattr used to format the string
            selected (bool | None): Selected or unselected formatting
    """
    def __init__(self, string: str, themeattr: ThemeAttr, selected: bool | None = False) -> None:
        if not (isinstance(string, str)
                and isinstance(themeattr, ThemeAttr)
                and (selected is None or isinstance(selected, bool))):
            errmsg = [
                [("ThemeStr()", "emphasis"),
                 (" initialised with invalid argument(s):", "error")],
                [("themefile = ", "default"),
                 (f"{ThemeStrConfiguration.themefile}", "path")],
                [("string = ", "default"),
                 (f"{string}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(string)}", "argument"),
                 (", expected: ", "default"),
                 ("str", "argument"),
                 (")", "default")],
                [("themeattr = ", "default"),
                 (f"{themeattr}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(themeattr)}", "argument"),
                 (", expected: ", "default"),
                 ("ThemeAttr", "argument"),
                 (")", "default")],
                [("selected = ", "default"),
                 (f"{selected}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(selected)}", "argument"),
                 (", expected: ", "default"),
                 ("bool", "argument"),
                 (")", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            raise ProgrammingError(unformatted_msg,
                                   subexception=TypeError,
                                   severity=LogLevel.ERR,
                                   facility=str(ThemeStrConfiguration.themefile),
                                   formatted_msg=formatted_msg)
        self.string = string
        self.themeattr = themeattr
        self.selected = selected

    def __str__(self) -> str:
        return self.string

    def __len__(self) -> int:
        return len(self.string)

    def __repr__(self) -> str:
        return f"ThemeStr('{self.string}', {self.themeattr!r}, {self.selected})"

    def get_themeattr(self) -> ThemeAttr:
        """
        Return the ThemeAttr attribute of the ThemeStr.

            Returns:
                (ThemeAttr): The ThemeAttr attribute of the ThemeStr
        """
        return self.themeattr

    def set_themeattr(self, themeattr: ThemeAttr) -> None:
        """
        Replace the ThemeAttr attribute of the ThemeStr.

            Parameters:
                themeattr (ThemeAttr): The new ThemeAttr attribute to use
        """
        self.themeattr = themeattr

    def get_selected(self) -> bool | None:
        """
        Return the selected attribute of the ThemeStr.

            Returns:
                (bool): The selected attribute of the ThemeStr
        """
        return self.selected

    def __eq__(self, obj: object) -> bool:
        if not isinstance(obj, ThemeStr):
            return False

        return repr(obj) == repr(self)


class ThemeRef:
    """
    A reference to a themed string;
    while the type definition is the same as ThemeAttr its use is different.

        Parameters:
            context: The context to use when doing a looking in themes
            key: The key to use when doing a looking in themes
            selected (bool | None): Should the selected or unselected formatting be used
    """
    def __init__(self, context: str, key: str, selected: bool | None = False) -> None:
        if not (isinstance(context, str)
                and isinstance(key, str)
                and (selected is None or isinstance(selected, bool))):
            errmsg = [
                [("ThemeRef()", "emphasis"),
                 (" initialised with invalid argument(s):", "error")],
                [("themefile = ", "default"),
                 (f"{ThemeStrConfiguration.themefile}", "path")],
                [("context = ", "default"),
                 (f"{context}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(context)}", "argument"),
                 (", expected: ", "default"),
                 ("str", "argument"),
                 (")", "default")],
                [("key = ", "default"),
                 (f"{key}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(key)}", "argument"),
                 (", expected: ", "default"),
                 ("str", "argument"),
                 (")", "default")],
                [("selected = ", "default"),
                 (f"{selected}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(selected)}", "argument"),
                 (", expected: ", "default"),
                 ("bool", "argument"),
                 (")", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   facility=str(ThemeStrConfiguration.themefile),
                                   formatted_msg=formatted_msg)
        self.context = context
        self.key = key
        self.selected = selected

    def __str__(self) -> str:
        string = ""
        data = deep_get(ThemeStrConfiguration.theme, DictPath(f"{self.context}#{self.key}"))
        if data is None:
            errmsg = [
                [("The ThemeRef(", "error"),
                 (f"'{self.context}'", "argument"),
                 (", ", "error"),
                 (f"'{self.key}'", "argument"),
                 (") does not exist.", "error")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            self.context = "strings"
            self.key = "themeref_missing"
            data = deep_get(ThemeStrConfiguration.theme, DictPath(f"{self.context}#{self.key}"))

        if isinstance(data, dict):
            if self.selected:
                selected = "selected"
            else:
                selected = "unselected"
            array = deep_get(data, DictPath(selected))
        else:
            array = data
        for string_fragment, _attr in array:
            string += string_fragment
        return string

    def __len__(self) -> int:
        return len(str(self))

    def __repr__(self) -> str:
        return f"ThemeRef('{self.context}', '{self.key}', {self.selected})"

    def to_themearray(self) -> list[ThemeStr]:
        """
        Return the themearray representation of the ThemeRef.

            Returns:
                (ThemeArray): The themearray representation
        """
        themearray = []
        data = deep_get(ThemeStrConfiguration.theme, DictPath(f"{self.context}#{self.key}"))
        if isinstance(data, dict):
            if self.selected:
                selected = "selected"
            else:
                selected = "unselected"
            array = deep_get(data, DictPath(selected))
        else:
            array = data
        if array is None:
            errmsg = [
                [("The ThemeRef(", "error"),
                 (f"'{self.context}'", "argument"),
                 (", ", "error"),
                 (f"'{self.key}'", "argument"),
                 (") does not exist.", "error")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   facility=str(ThemeStrConfiguration.themefile),
                                   formatted_msg=formatted_msg)
        for string, themeattr in array:
            themearray.append(ThemeStr(string,
                                       ThemeAttr(themeattr[0], themeattr[1]),
                                       self.selected))
        return themearray

    def get_selected(self) -> bool | None:
        """
        Return the selected attribute of the ThemeRef.

            Returns:
                (bool): The selected attribute of the ThemeRef, None if unset
        """
        return self.selected

    def __eq__(self, obj: object) -> bool:
        if not isinstance(obj, ThemeRef):
            return False

        return repr(obj) == repr(self)


class ThemeArray:
    """
    An array of themed strings and references to themed strings.

        Parameters:
            [ThemeStr|ThemeRef]: The themearray
            selected (bool): Selected or unselected formatting;
                             passing this parameter overrides
                             individual members of the ThemeArray
    """
    def __init__(self, array: list[ThemeRef | ThemeStr],
                 selected: bool | None = None) -> None:
        if array is None:
            errmsg = [
                [("ThemeArray()", "emphasis"),
                 (" initialised with an empty array", "error")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   facility=str(ThemeStrConfiguration.themefile),
                                   formatted_msg=formatted_msg)

        if not isinstance(array, list):
            errmsg = [
                [("ThemeArray()", "emphasis"),
                 (" initialised with invalid argument(s):", "error")],
                [("array = ", "default"),
                 (f"{array}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(array)}", "argument"),
                 (", expected: ", "default"),
                 ("list", "argument"),
                 (")", "default")],
                [("selected = ", "default"),
                 (f"{selected}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(selected)}", "argument"),
                 (", expected: ", "default"),
                 ("bool", "argument"),
                 (")", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   facility=str(ThemeStrConfiguration.themefile),
                                   formatted_msg=formatted_msg)

        newarray: list[ThemeRef | ThemeStr] = []
        for item in array:
            if not isinstance(item, (ThemeRef, ThemeStr)):
                errmsg = [
                    [("ThemeArray()", "emphasis"),
                     (" initialised with invalid argument(s):", "error")],
                    [("array element = ", "default"),
                     (f"{item}", "argument"),
                     (" (type: ", "default"),
                     (f"{type(item)}", "argument"),
                     (", expected: ", "default"),
                     ("ThemeRef", "argument"),
                     (" or ", "default"),
                     ("ThemeStr", "argument"),
                     (")", "default")],
                ]
                unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                raise ProgrammingError(unformatted_msg,
                                       severity=LogLevel.ERR,
                                       facility=str(ThemeStrConfiguration.themefile),
                                       formatted_msg=formatted_msg)
            if selected is None:
                newarray.append(item)
            elif isinstance(item, ThemeStr):
                newarray.append(ThemeStr(item.string, item.themeattr, selected=selected))
            elif isinstance(item, ThemeRef):
                newarray.append(ThemeRef(item.context, item.key, selected=selected))

        self.array = newarray

    def append(self, item: ThemeRef | ThemeStr) -> None:
        """
        Append a ThemeRef or ThemeStr to the ThemeArray.

            Parameters:
                item (union(ThemeRef, ThemeStr)): The item to append
        """
        if not isinstance(item, (ThemeRef, ThemeStr)):
            errmsg = [
                [("ThemeArray.append()", "emphasis"),
                 (" called with invalid argument(s):", "error")],
                [("item = ", "default"),
                 (f"{item}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(item)}", "argument"),
                 (", expected: ", "default"),
                 ("ThemeRef", "argument"),
                 (" or ", "default"),
                 ("ThemeStr", "argument"),
                 (")", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   facility=str(ThemeStrConfiguration.themefile),
                                   formatted_msg=formatted_msg)
        self.array.append(item)

    # We need to use Union here since we have a forward declaration.
    # pylint: disable-next=line-too-long
    def __add__(self, array: Union["ThemeArray", list[Union[ThemeRef, ThemeStr]]]) -> "ThemeArray":  # noqa: UP007,E501
        if isinstance(array, ThemeArray):
            return ThemeArray(self.to_list() + array.to_list())

        if not isinstance(array, list):
            errmsg = [
                [("ThemeArray.__add__()", "emphasis"),
                 (" called with invalid argument(s):", "error")],
                [("array = ", "default"),
                 (f"{array}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(array)}", "argument"),
                 (", expected: ", "default"),
                 ("ThemeArray", "argument"),
                 (" or ", "default"),
                 ("[ThemeRef|ThemeStr]", "argument"),
                 (")", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   facility=str(ThemeStrConfiguration.themefile),
                                   formatted_msg=formatted_msg)

        return ThemeArray(self.to_list() + array)

    def __str__(self) -> str:
        string = ""
        for item in self.array:
            string += str(item)
        return string

    def __len__(self) -> int:
        arraylen = 0
        for item in self.array:
            arraylen += len(item)
        return arraylen

    def __repr__(self) -> str:
        references = ""
        first = True
        for item in self.array:
            if first:
                references += f"{item!r}"
            else:
                references += f", {item!r}"
            first = False
        return f"ThemeArray([{references}])"

    def __eq__(self, obj: object) -> bool:
        if not isinstance(obj, ThemeArray):
            return False

        return repr(obj) == repr(self)

    def to_list(self) -> list[ThemeRef | ThemeStr]:
        """
        Return the ThemeArray as a list of ThemeRef | ThemeStr.

            Returns:
                ([ThemeRef|ThemeArray]): The list of ThemeRef | ThemeStr
        """
        return self.array
