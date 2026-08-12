#! /usr/bin/env python3
# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

# pylint: disable=too-many-lines

"""
Module for ThemeStr / ThemeAttr / ThemeRef / ThemeArray.
"""

import curses
from pathlib import Path, PurePath
from typing import Any, cast, NamedTuple

from clustermanagementtoolkit.cmttypes import DictPath, FilePath, LogLevel
from clustermanagementtoolkit.cmttypes import FilePathAuditError, ProgrammingError
from clustermanagementtoolkit.cmttypes import SecurityChecks, SecurityStatus
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cmtpaths import SYSTEM_DEFAULT_THEME_FILE

from clustermanagementtoolkit.cmtio import check_path, join_securitystatus_set

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

theme: dict = {}
themefile: FilePath | None = None  # pylint: disable=invalid-name


def get_theme_ref() -> dict:
    """
    Get a reference to the theme.

        Returns:
            (str): A reference to the theme
    """
    return theme


theme_colors: dict[str, tuple[int, int]] = {}


color_map: dict[str, int] = {
    "black": curses.COLOR_BLACK,
    "red": curses.COLOR_RED,
    "green": curses.COLOR_GREEN,
    "yellow": curses.COLOR_YELLOW,
    "blue": curses.COLOR_BLUE,
    "magenta": curses.COLOR_MAGENTA,
    "cyan": curses.COLOR_CYAN,
    "white": curses.COLOR_WHITE,
}


def read_theme(configthemefile: FilePath, defaultthemefile: FilePath) -> None:
    """
    Read the theme file and initialise the theme dict.

        Parameters:
            configthemefile (FilePath): The theme to read
            defaultthemefile (FilePath): The fallback if the other theme is not available
    """
    global theme  # pylint: disable=global-statement
    global themefile  # pylint: disable=global-statement

    for item in (configthemefile, f"{configthemefile}.yaml",
                 defaultthemefile, SYSTEM_DEFAULT_THEME_FILE):
        if item is not None and Path(item).is_file():
            themefile = cast(FilePath, item)
            break

    if themefile is None:
        if configthemefile:
            errmsg = [
                [("Failed to load themefile ", "error"),
                 (f"{configthemefile}", "path"),
                 ("; file not found.", "error")],
            ]
        elif defaultthemefile:
            errmsg = [
                [("Failed to load default themefile ", "error"),
                 (f"{defaultthemefile}", "path"),
                 ("; file not found.", "error")],
            ]
        else:
            errmsg = [
                [("Failed to load themefile; both the configthemefile "
                  "and the defaultthemefile paths are empty", "error")],
            ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        raise ProgrammingError(unformatted_msg,
                               subexception=FileNotFoundError,
                               severity=LogLevel.ERR,
                               formatted_msg=formatted_msg)

    # The parsers directory itself may be a symlink.
    # This is expected behaviour when installing from a git repo,
    # but we only allow it if the rest of the path components are secure.
    checks = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_DIR,
    ]

    theme_dir = FilePath(PurePath(themefile).parent)

    violations = check_path(theme_dir, checks=checks)
    if violations != [SecurityStatus.OK]:
        violations_joined = join_securitystatus_set(",", set(violations))
        errmsg = [
            [("FilePathAuditError: ", "emphasis")],
            [(f"Violated rules: {violations_joined}", "error")],
            [("Path: ", "error"),
             (f"{theme_dir}", "path")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        raise FilePathAuditError(f"Violated rules: {violations_joined}", path=theme_dir)

    # We do not want to check that parent resolves to itself,
    # because when we have an installation with links directly to the git repo
    # the themes directory will be a symlink
    checks = [
        SecurityChecks.RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_FILE,
    ]

    theme = dict(secure_read_yaml(FilePath(themefile), checks=checks, asynchronous=True))


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
                 (f"{themefile}", "path")],
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
                                   facility=str(themefile),
                                   formatted_msg=formatted_msg)
        self.string = string
        self.themeattr = themeattr
        self.selected = selected

    def __str__(self) -> str:
        return self.string

    def __len__(self) -> int:
        return len(self.string)

    def __repr__(self) -> str:
        return f"ThemeStr('{self.string}', {repr(self.themeattr)}, {self.selected})"

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

    def __eq__(self, obj: Any) -> bool:
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
                 (f"{themefile}", "path")],
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
                                   facility=str(themefile),
                                   formatted_msg=formatted_msg)
        self.context = context
        self.key = key
        self.selected = selected

    def __str__(self) -> str:
        string = ""
        data = deep_get(theme, DictPath(f"{self.context}#{self.key}"))
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
            data = deep_get(theme, DictPath(f"{self.context}#{self.key}"))

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
        data = deep_get(theme, DictPath(f"{self.context}#{self.key}"))
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
                                   facility=str(themefile),
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

    def __eq__(self, obj: Any) -> bool:
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
                                   facility=str(themefile),
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
                                   facility=str(themefile),
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
                                       facility=str(themefile),
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
                                   facility=str(themefile),
                                   formatted_msg=formatted_msg)
        self.array.append(item)

    # We need to use Union here since we have a forward declaration.
    def __add__(self, array: "ThemeArray") -> "ThemeArray":
        """
        Concatenates two ThemeArrays, and returns the result.

            Parameters:
                item (ThemeArray): The item to append
            Returns:
                (ThemeArray): The concatenation of the two ThemeArrays
        """
        return ThemeArray(self.to_list() + array.to_list())

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
                references += f"{repr(item)}"
            else:
                references += f", {repr(item)}"
            first = False
        return f"ThemeArray([{references}])"

    def __eq__(self, obj: Any) -> bool:
        if not isinstance(obj, ThemeArray):
            return False

        return repr(obj) == repr(self)

    def flatten(self) -> "ThemeArray":
        """
        Return a flattened ThemeArray; all ThemeRefs will be expanded to ThemeStr().
        """
        flattened = []

        for segment in self.array:
            if isinstance(segment, ThemeStr):
                flattened.append(segment)
            elif isinstance(segment, ThemeRef):
                flattened += segment.to_themearray()
        return flattened

    def uncompact(self) -> "ThemeArray":
        """
        Return an uncompacted ThemeArray; every character in the array
        will become its own ThemeStr. This makes slicing, splitting,
        and other transformations much easier.

            Returns:
                (ThemeArray): An uncompacted ThemeArray
        """
        uncompacted: list[ThemeRef | ThemeStr] = []

        for segment in self.flatten():
            string = str(segment)
            attr = segment.get_themeattr()
            selected = segment.get_selected()
            for char in string:
                uncompacted.append(ThemeStr(char, attr, selected=selected))
        return uncompacted

    def compact(self) -> "ThemeArray":
        """
        Return a compacted ThemeArray; merge all adjacent substrings with identical
        formatting into one substring.

            Returns:
                (ThemeArray): A compacted ThemeArray
        """
        compacted: list[ThemeRef | ThemeStr] = []

        tmp_string: str = None
        tmp_attr: ThemeAttr = None
        tmp_selected: bool = None

        for segment in self.array:
            string = str(segment)
            attr = segment.get_themeattr()
            selected = segment.get_selected()
            if attr != tmp_attr or selected != tmp_selected:
                if tmp_string is not None:
                    compacted.append(ThemeStr(tmp_string, attr, selected=selected))
                tmp_string = string
                tmp_attr = attr
                tmp_selected = selected
            else:
                tmp_string += string

        if tmp_string is not None:
            compacted.append(ThemeStr(tmp_string, attr, selected=selected))
        return compacted

    def __getitem__(self, subscript: slice) -> "ThemeArray":
        """
        Return the flattened and compacted slice of the ThemeArray.

            Parameters:
                subscript (slice): (start, stop, step)
            Returns:
                (ThemeArray): The sliced, flattened, and compacted ThemeArray.
        """
        newarray = []
        start = subscript.start
        end = subscript.stop
        step = subscript.step

        newarray = self.uncompact()[start:end:step]
        return ThemeArray(newarray).compact()

    def to_list(self) -> list[ThemeRef | ThemeStr]:
        """
        Return the ThemeArray as a list of ThemeRef | ThemeStr.

            Returns:
                ([ThemeRef|ThemeArray]): The list of ThemeRef | ThemeStr
        """
        return self.array

    def select(self, selected: bool = False, force: bool = False) -> None:
        """
        Iterate through the themearray and set all selected fields that are currently None.

            Parameters:
                selected (bool): True is selected, False otherwise
                force (bool): True to set selected=selected even if item.seleected isn't None
        """
        newarray: list[ThemeRef | ThemeStr] = []

        for segment in self.array:
            if segment.selected is None or force:
                segment.selected = selected
            newarray.append(segment)
        self.array = newarray


def themearray_wrap_line(themearray: ThemeArray, maxwidth: int = -1,
                         wrap_marker: bool = True) -> list[ThemeArray]:
    """
    Given a themearray, split it into multiple lines, each maxwidth long.

        Parameters:
            themearray (ThemeArray): The themearray to wrap
            maxwidth (int): The maximum number of characters before wrapping
            wrap_marker (bool): Should the line end in a wrap marker?
        Returns:
            ([ThemeArray]): A list of themearrays
    """
    if maxwidth == -1:
        return [themearray]

    if not (themearray_flat := themearray.flatten()):
        return []

    linebreak = ThemeRef("separators", "line_break").to_themearray()

    if wrap_marker:
        linebreaklen = len(linebreak)
    else:
        linebreaklen = 0

    themearrays: list[ThemeArray] = []
    tmp_themearray: list[ThemeRef | ThemeStr] = []
    tmplen = 0
    i = 0

    while True:
        # Does the fragment fit?
        tfilen = len(themearray_flat[i])
        if tmplen + tfilen < maxwidth:
            tmp_themearray.append(themearray_flat[i])
            tmplen += tfilen
            i += 1
        # Nope
        else:
            string = str(themearray_flat[i])
            themeattr = themearray_flat[i].get_themeattr()

            tmp_themearray.append(ThemeStr(string[:maxwidth - linebreaklen - tmplen], themeattr))
            if wrap_marker:
                tmp_themearray += linebreak
            themearray_flat[i] = ThemeStr(string[maxwidth - linebreaklen - tmplen:], themeattr)
            themearrays.append(ThemeArray(tmp_themearray))
            tmp_themearray = []
            tmplen = 0
            continue
        if i == len(themearray_flat):
            themearrays.append(ThemeArray(tmp_themearray))
            break

    return themearrays


# pylint: disable-next=too-many-branches
def themeattr_to_curses(themeattr: ThemeAttr, selected: bool = False) -> tuple[int, int]:
    """
    Given a themeattr returns a tuple with curses color + curses attributes.

        Parameters:
            themeattr (ThemeAttr): The ThemeAttr to convert
            selected (bool): [optional] True is selected, False otherwise
        Returns:
            (int, int):
                (int): A curses color
                (int): Curses attributes
    """
    context, key = themeattr
    tmp_attr = deep_get(theme, DictPath(f"{context}#{key}"))

    if tmp_attr is None:
        errmsg = [
            [("Could not find the tuple (", "default"),
             (f"{context}", "argument"),
             (", ", "default"),
             (f"{key}", "argument"),
             (") in themefile ", "default"),
             (f"{themefile}", "path")],
            [("Using (", "default"),
             ("main", "argument"),
             (", ", "default"),
             ("default", "argument"),
             (") as fallback.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        tmp_attr = deep_get(theme, DictPath("main#default"))

    if isinstance(tmp_attr, dict):
        if selected:
            attr = tmp_attr["selected"]
        else:
            attr = tmp_attr["unselected"]
    else:
        attr = tmp_attr

    if isinstance(attr, list):
        col, attr = attr
    else:
        col = attr
        attr = "normal"

    if isinstance(attr, str):
        attr = [attr]
    else:
        attr = list(attr)

    tmp = 0

    for item in attr:
        if not isinstance(item, str):
            errmsg = [
                [("Invalid text attribute used in themefile ", "default"),
                 (f"{themefile}", "path"),
                 ("; attribute has to be a string and one of:", "default")],
                [("“", "default"),
                 ("dim", "argument"),
                 ("“, “", "default"),
                 ("normal", "argument"),
                 ("“, “", "default"),
                 ("bold", "argument"),
                 ("“, “", "default"),
                 ("underline", "argument"),
                 ("“.", "default")],
                [("Using “", "default"),
                 ("normal", "argument"),
                 ("“ as fallback.", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            item = "normal"
        if item == "dim":
            tmp |= curses.A_DIM
        elif item == "normal":
            tmp |= curses.A_NORMAL
        elif item == "bold":
            tmp |= curses.A_BOLD
        elif item == "italics":
            tmp |= curses.A_ITALIC
        elif item == "underline":
            tmp |= curses.A_UNDERLINE
        else:
            errmsg = [
                [("Invalid text attribute “", "default"),
                 (f"{item}", "emphasis"),
                 ("“ used in themefile ", "default"),
                 (f"{themefile}", "path"),
                 ("; attribute has to be one of:", "default")],
                [("“", "default"),
                 ("dim", "argument"),
                 ("“, “", "default"),
                 ("normal", "argument"),
                 ("“, “", "default"),
                 ("bold", "argument"),
                 ("“, “", "default"),
                 ("underline", "argument"),
                 ("“.", "default")],
                [("Using “", "default"),
                 ("normal", "argument"),
                 ("“ as fallback.", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            tmp |= curses.A_NORMAL
    curses_attrs = tmp

    curses_col = theme_colors[col][selected]
    if curses_col is None:
        errmsg = [
            [("Non-existing (color, selected) tuple ", "default")],
            [(f"{col}", "argument")],
            [(", ", "default")],
            [(f"{selected}", "argument")],
            [(").", "default")],
            [("Using first defined tuple as fallback.", "default")],
        ]
        curses_col = theme_colors[0][selected]
    return curses_col, curses_attrs


def themeattr_to_curses_merged(themeattr: ThemeAttr, selected: bool = False) -> int:
    """
    Given a themeattr returns merged curses color + curses attributes.

        Parameters:
            themeattr (ThemeAttr): The ThemeAttr to convert
            selected (bool): [optional] True is selected, False otherwise
        Returns:
            (int): Curses color | attrs
    """
    curses_col, curses_attrs = themeattr_to_curses(themeattr, selected)
    return curses_col | curses_attrs


def themestr_to_cursestuple(themestr: ThemeStr, selected: bool | None = None) -> tuple[str, int]:
    """
    Given a ThemeStr returns a cursestuple.

        Parameters:
            themestr (ThemeStr): The ThemeStr to convert
            selected (bool): [optional] True is selected, False otherwise
        Returns:
            (str, int): A curses tuple for use with addformattedarray()
    """
    string = str(themestr)
    themeattr = themestr.get_themeattr()

    if selected is None:
        selected = themestr.get_selected()
        if selected is None:
            selected = False

    return (string, themeattr_to_curses_merged(themeattr, selected))


def themearray_detab(themearray: ThemeArray, selected: bool | None = None) -> ThemeArray:
    """
    Replace all tabs in a ThemeArray with spaces.

        Parameters:
            themearray (ThemeArray): The themearray to detab
        Returns:
            (ThemeArray): The detabbed themearray
    """
    themearray_detabbed: list[ThemeRef | ThemeStr] = []
    length = 0

    for segment in themearray:
        if isinstance(segment, ThemeRef):
            length += len(ThemeArray([segment]))
            themearray_detabbed.append(segment)
        elif isinstance(segment, ThemeStr):
            # We need to replace tabs with spaces; it's not a trivial process and we cannot get it
            # perfect, but we'll do what we can.
            tabsplit = str(segment).split("\t")
            if len(tabsplit) > 1:
                new_string = ""
                tab = ""
                for subsegment in tabsplit:
                    new_string += tab
                    new_string += subsegment
                    tabsize = (length + len(new_string)) % 8
                    if not tabsize:
                        tabsize = 8
                    tab = "".ljust(tabsize)
            else:
                new_string = str(segment)
            # Replace the string component of the ThemeStr()
            segment.string = new_string
            themearray_detabbed.append(segment)
            length += len(new_string)
    return ThemeArray(themearray_detabbed)


def themearray_replace(themearray: ThemeArray,
                       oldvalue: str, newvalue: str, count: int = -1) -> ThemeArray:
    """
    Search and replace for needle in haystack.
    Note: Currently only single character replace is supported.

        Parameters:
            themearray (ThemeArray): The themearray to substitute characters in
            oldvalue (str): The character search for
            newvalue (str): The character to replace with
        Returns:
            (ThemeArray): The modified themearray
    """
    new_themearray: list[ThemeRef | ThemeStr] = []

    for segment in themearray:
        if isinstance(segment, ThemeRef):
            new_themearray.append(segment)
            continue

        themeattr = segment.themeattr
        for char in str(segment):
            if count and char == oldvalue:
                char = newvalue
                count -= 1
            new_themearray.append(ThemeStr(char, themeattr))

    return ThemeArray(new_themearray).compact()


def themearray_split(themearray: ThemeArray, separator: str = " ") -> list[ThemeArray]:
    """
    Perform split() on a ThemeArray.

        Parameters:
            themearray (ThemeArray): The themearray to split
            separator (str): The character to split on
        Returns:
            ([ThemeArray]): A splitted themearray
    """
    themearrays: list[ThemeArray] = []
    tmp_themearray: list[ThemeStr] = []

    # The only easy way to split a themearray string is to iterate over every single segment,
    # then over every single character in the segment and reconstruct the constituent parts
    # until we encounter the separator and then flush.
    for segment in themearray:
        themeattr = segment.get_themeattr()

        for char in str(segment):
            if char == separator:
                themearrays.append(tmp_themearray)
                tmp_themearray = []
                continue
            tmp_themearray.append(ThemeStr(char, themeattr))
    if tmp_themearray:
        themearrays.append(ThemeArray(tmp_themearray))

    return themearrays


def themearray_lstrip(themearray: ThemeArray, characters: str = " ") -> ThemeArray:
    """
    Perform lstrip() on a ThemeArray.

        Parameters:
            themearray (ThemeArray): The themearray to lstrip
            characters (str): The characters to strip
        Returns:
            (ThemeArray): An lstripped themearray
    """
    new_themearray: list[ThemeStr] = []

    for segment in themearray:
        # Skip completely empty leading elements
        if not new_themearray:
            if not str(segment).strip(characters):
                continue
            new_themearray.append(ThemeStr(str(segment).lstrip(characters),
                                           segment.get_themeattr()))
            continue
        new_themearray.append(segment)
    return ThemeArray(new_themearray)


def themearray_rstrip(themearray: ThemeArray, characters: str = " ") -> ThemeArray:
    """
    Perform rstrip() on a ThemeArray.

        Parameters:
            themearray (ThemeArray): The themearray to rstrip
            characters (str): The characters to strip
        Returns:
            (ThemeArray): An rstripped themearray
    """
    new_themearray: list[ThemeStr] = []

    for segment in reversed(themearray):
        # Skip completely empty leading elements
        if not new_themearray:
            if not str(segment).strip(characters):
                continue
            new_themearray.append(ThemeStr(str(segment).rstrip(characters),
                                           segment.get_themeattr()))
            continue
        new_themearray.append(segment)
    return ThemeArray(list(reversed(new_themearray)))


def themearray_strip(themearray: ThemeArray, characters: str = " ") -> ThemeArray:
    """
    Perform strip() on a ThemeArray.

        Parameters:
            themearray (ThemeArray): The themearray to strip
            characters (str): The characters to strip
        Returns:
            (ThemeArray): An stripped themearray
    """
    return themearray_lstrip(themearray_rstrip(themearray, characters), characters)
