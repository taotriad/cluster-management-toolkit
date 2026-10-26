# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A class for formatted strings.
"""

import copy
from typing import Self

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


class ANSIThemeStr:
    """
    A themed string for printing with ANSI control codes

        Parameters:
            string: A string
            themeref: The reference to use when doing a looking in themes
    """

    def __init__(self, string: str, themeref: str) -> None:
        """
        Initialize an ANSIThemeStr

            Parameters:
                string (str): The string to format
                themeref (str): The reference to the formatting to use
        """
        if not isinstance(string, str) or not isinstance(themeref, str):
            raise TypeError("ANSIThemeStr only accepts (str, str); "
                            f"received ({type(string)}, {type(themeref)})")
        self.string = str(string)
        self.themeref = str(themeref)

    def __str__(self) -> str:
        """
        Return the string part of the ANSIThemeStr

            Returns:
                (str): The string part of the ANSIThemeStr
        """
        return self.string

    def __len__(self) -> int:
        """
        Return the length to the ANSIThemeStr

            Returns:
                (int): The length of the ANSIThemeStr
        """
        return len(self.string)

    def __repr__(self) -> str:
        return f"ANSIThemeStr(string=\"{self.string}\", themeref=\"{self.themeref}\")"

    def format(self, themeref: str) -> Self:
        """
        Apply new formatting to the ANSIThemeStr

            Parameters:
                themeref (str): The reference to the formatting part of the ANSIThemeStr
            Returns:
                (ANSIThemeStr): The ANSIThemeStr with new formatting applied
        """
        if not isinstance(themeref, str):
            raise TypeError("ANSIThemeStr().format() only accepts (str); "
                            f"received ({type(themeref)})")
        self.themeref = str(themeref)
        return self

    def get_themeref(self) -> str:
        """
        Return the reference to the formatting part of the ANSIThemeStr

            Returns:
                (str): The reference to the formatting part of the ANSIThemeStr
        """
        return self.themeref

    def upper(self) -> "ANSIThemeStr":
        """
        Return the upper-case version of the ANSIThemeStr

            Returns:
                (ANSIThemeStr): The upper-case version of the ANSIThemeStr
        """
        return ANSIThemeStr(self.string.upper(), self.themeref)

    def lower(self) -> "ANSIThemeStr":
        """
        Return the lower-case version of the ANSIThemeStr

            Returns:
                (ANSIThemeStr): The lower-case version of the ANSIThemeStr
        """
        return ANSIThemeStr(self.string.lower(), self.themeref)

    def capitalize(self) -> "ANSIThemeStr":
        """
        Return the capitalised version of the ANSIThemeStr

            Returns:
                (ANSIThemeStr): The capitalized version of the ANSIThemeStr
        """
        return ANSIThemeStr(self.string.capitalize(), self.themeref)

    def __eq__(self, themestring: object) -> bool:
        """
        Compare two ANSIThemeStrs and return True if both string and formatting are identical

            Parameters:
                themestring (ANSIThemeStr): The ANSIThemeStr to compare to
            Returns:
                (bool): True if the strings match, False if not
        """
        return isinstance(themestring, ANSIThemeStr) \
            and self.string == themestring.string \
            and self.themeref == themestring.themeref

    @classmethod
    def ansithemearray_to_tuplelist(cls, msg: list["ANSIThemeStr"]) -> list[tuple[str, str]]:
        """
        Given an ANSIThemeArray return its tuple representation

            Parameters:
                msg ([ANSIThemeStr]): An ANSIThemeArray to reformat
            Returns:
                ([(str, str)]): A list of tuples representing the ANSIThemeArray
        """
        tuplelist = []

        if not isinstance(msg, list):
            raise ProgrammingError("ANSIThemeStr.ansithemearray_to_tuplelist() "
                                   "called with invalid argument(s):\n"
                                   f"msg={msg} (type: {type(msg)}, expected: list)",
                                   subexception=TypeError,
                                   severity=LogLevel.ERR,
                                   formatted_msg=[[("ANSIThemeStr.ansithemearray_to_tuplelist()",
                                                    "emphasis"),
                                                   (" called with invalid argument(s):", "error")],
                                                  [("msg = ", "default"),
                                                   (f"{msg}", "argument"),
                                                   (" (type: ", "default"),
                                                   (f"{type(msg)}", "argument"),
                                                   (", expected: ", "default"),
                                                   ("list", "argument"),
                                                   (")", "default")]])

        for item in msg:
            if not isinstance(item, ANSIThemeStr):
                raise ProgrammingError("ANSIThemeStr.ansithemearray_to_tuplelist() "
                                       "called with invalid argument(s):\n"
                                       f"msg={msg} (type: {type(msg)}, "
                                       "expected: list[ANSIThemeStr])",
                                       subexception=TypeError,
                                       severity=LogLevel.ERR,
                                       formatted_msg=[
                                           [("ANSIThemeStr.ansithemearray_to_tuplelist()",
                                             "emphasis"),
                                            (" called with invalid argument(s):", "error")],
                                           [("msg = ", "default"),
                                            (f"{msg}", "argument"),
                                            (" (type: ", "default"),
                                            (f"{type(msg)}", "argument"),
                                            (", expected: ", "default"),
                                            ("list", "argument"),
                                            (")", "default")]])
            tuplelist.append((str(item), item.themeref))
        return tuplelist

    @classmethod
    def tuplelist_to_ansithemearray(cls, msg: list[tuple[str, str]]) -> list["ANSIThemeStr"]:
        """
        Given a structured message return its ANSIThemeArray representation

            Parameters:
                msg ([(str, str)]): A structured message for format
            Returns:
                (ANSIThemeArray): The ANSIThemeArray representations of the message
            Raises:
                ProgrammingError(TypeError): Invalid indata
        """
        themearray = []

        if not isinstance(msg, list):
            raise ProgrammingError("ANSIThemeStr.tuplelist_to_ansithemearray() "
                                   "called with invalid argument(s):\n"
                                   f"msg={msg} (type: {type(msg)}, expected: list)",
                                   subexception=TypeError,
                                   severity=LogLevel.ERR,
                                   formatted_msg=[[("ANSIThemeStr.tuplelist_to_ansithemearray()",
                                                    "emphasis"),
                                                   (" called with invalid argument(s):", "error")],
                                                  [("msg = ", "default"),
                                                   (f"{msg}", "argument"),
                                                   (" (type: ", "default"),
                                                   (f"{type(msg)}", "argument"),
                                                   (", expected: ", "default"),
                                                   ("list", "argument"),
                                                   (")", "default")]])

        for item in msg:
            if not (isinstance(item, tuple) and len(item) == 2
                    and isinstance(item[0], str) and isinstance(item[1], str)):
                raise ProgrammingError("ANSIThemeStr.tuplelist_to_ansithemearray() "
                                       "called with invalid argument(s):\n"
                                       f"msg={msg} (type: {type(msg)}, expected: list[(str, str)])",
                                       subexception=TypeError,
                                       severity=LogLevel.ERR,
                                       formatted_msg=[
                                           [("ANSIThemeStr.tuplelist_to_ansithemearray()",
                                             "emphasis"),
                                            (" called with invalid argument(s):", "error")],
                                           [("msg = ", "default"),
                                            (f"{msg}", "argument"),
                                            (" (type: ", "default"),
                                            (f"{type(msg)}", "argument"),
                                            (", expected: ", "default"),
                                            ("list", "argument"),
                                            (")", "default")]])
            themearray.append(ANSIThemeStr(item[0], item[1]))
        return themearray

    @classmethod
    def format_error_msg(cls, msg: list[list[tuple[str, str]]]) -> \
            tuple[str, list[list["ANSIThemeStr"]]]:
        """
        Given a structured error message return both its string and ANSIThemeArray representations;
        the main use-case for this is to feed into enhanced exceptions that accept
        both formatted and plaintext strings.

            Parameters:
                msg ([[(str, str)]]): A structured message for format
            Returns:
                (str, [ANSIThemeArray]): The string and ANSIThemeArray
                                         representations of the message
            Raises:
                ProgrammingError(TypeError): Invalid indata
        """
        joined_strings = []
        themearray_list = []

        if not isinstance(msg, list):
            raise ProgrammingError("ANSIThemeStr.format_error_msg() "
                                   "called with invalid argument(s):\n"
                                   f"msg={msg} (type: {type(msg)}, expected: list)",
                                   subexception=TypeError,
                                   severity=LogLevel.ERR,
                                   formatted_msg=[[("ANSIThemeStr.format_error_msg()",
                                                    "emphasis"),
                                                   (" called with invalid argument(s):", "error")],
                                                  [("msg = ", "default"),
                                                   (f"{msg}", "argument"),
                                                   (" (type: ", "default"),
                                                   (f"{type(msg)}", "argument"),
                                                   (", expected: ", "default"),
                                                   ("list", "argument"),
                                                   (")", "default")]])

        for line in msg:
            if not isinstance(line, list):
                raise ProgrammingError("ANSIThemeStr.format_error_msg() "
                                       "called with invalid argument(s):\n"
                                       f"line={line} (type: {type(line)}, expected: list)",
                                       subexception=TypeError,
                                       severity=LogLevel.ERR,
                                       formatted_msg=[[("ANSIThemeStr.format_error_msg()",
                                                        "emphasis"),
                                                       (" called with invalid argument(s):",
                                                        "error")],
                                                      [("line=", "default"),
                                                       (f"{line}", "argument"),
                                                       (" (type: ", "default"),
                                                       (f"{type(line)}", "argument"),
                                                       (", expected: ", "default"),
                                                       ("list", "argument"),
                                                       (")", "default")]])

            themearray = []
            joined_string = ""
            for items in line:
                if not (isinstance(items, tuple) and len(items) == 2
                        and isinstance(items[0], str) and isinstance(items[1], str)):
                    raise ProgrammingError("ANSIThemeStr.format_error_msg() "
                                           "called with invalid argument(s):\n"
                                           f"items={items} (type: {type(items)}, "
                                           "expected: tuple(str, str))",
                                           subexception=TypeError,
                                           severity=LogLevel.ERR,
                                           formatted_msg=[[("ANSIThemeStr.format_error_msg()",
                                                            "emphasis"),
                                                           (" called with invalid argument(s):",
                                                            "error")],
                                                          [("items=", "default"),
                                                           (f"{items}", "argument"),
                                                           (" (type: ", "default"),
                                                           (f"{type(items)}", "argument"),
                                                           (", expected: ", "default"),
                                                           ("tuple(str, str)", "argument"),
                                                           (")", "default")]])

                string, formatting = items
                joined_string += string
                themearray.append(ANSIThemeStr(string, formatting))
            themearray_list.append(copy.deepcopy(themearray))
            joined_strings.append(joined_string)

        return "\n".join(joined_strings), themearray_list
