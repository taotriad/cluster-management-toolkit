# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format the output from iptables.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_to_string


# pylint: disable-next=too-many-locals,too-many-branches
def iptables(message: str,
             remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]], **kwargs: Any) \
        -> tuple[str, LogLevel, list[ThemeRef | ThemeStr],
                 list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Format output from iptables-save.

        Parameters:
            message (str): The message part of the msg to format
            remnants (list[(themearray, severity)]): The remnants part of the msg to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
                fold_msg (bool): Should the message be expanded or folded?
                options (dict): Additional, rule specific, options
        Returns:
            (ThemeArray, LogLevel, str, [(ThemeArray, LogLevel)]):
                (str): The facility of the message
                (LogLevel): The LogLevel of the message
                (ThemeArray): The formatted message
                ([(ThemeArray, LogLevel)]):
                    (ThemeArray): The formatted strings of the remnant
                    (LogLevel): The severity of the remnant
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.DEFAULT)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)

    new_message: list[ThemeRef | ThemeStr] = []
    new_remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

    old_messages: list[str] = []
    if fold_msg and "\\n" in message:
        old_messages = message.split("\\n")
    else:
        old_messages.append(message)

        for themearray, _loglevel in remnants:
            old_messages.append(themearray_to_string(themearray))

    programname_regex = re.compile(r"^/.+?iptables$|"
                                   r"^/.+?iptables-save$|"
                                   r"^/.+?iptables-legacy$|"
                                   r"^/.+?iptables-legacy-save$|"
                                   r"^/.+?iptables-nft$|"
                                   r"^/.+?iptables-nft-save$")

    variable_regex = re.compile(r"^[A-Z][A-Z0-9_]*=.*")
    for i, items in enumerate(old_messages):
        tmp_message: list[ThemeRef | ThemeStr] = []
        for j, item in enumerate(items.split(" ")):
            # Variables consume the entire line
            if variable_regex.match(items) is not None:
                tmp_message.append(ThemeStr(items,
                                   ThemeAttr("types", "iptables_variable")))
                break

            if not j:
                if programname_regex.match(item):
                    tmp_message.append(ThemeStr(item,
                                       ThemeAttr("types", "iptables_programname")))
                elif item.startswith("*"):
                    tmp_message.append(ThemeStr(item,
                                       ThemeAttr("types", "iptables_table")))
                elif item.startswith(":"):
                    tmp_message.append(ThemeStr(item,
                                       ThemeAttr("types", "iptables_chain")))
                elif item.startswith("COMMIT"):
                    tmp_message.append(ThemeStr(item,
                                       ThemeAttr("types", "iptables_command")))
                elif item.startswith("-"):
                    tmp_message.append(ThemeStr(item,
                                       ThemeAttr("types", "iptables_option")))
                elif item.startswith("#"):
                    tmp_message.append(ThemeStr(items[j:],
                                       ThemeAttr("types", "iptables_comment")))
                    break
            elif item.startswith("-"):
                tmp_message.append(ThemeStr(f" {item}",
                                   ThemeAttr("types", "iptables_option")))
            elif item.startswith("#"):
                tmp_message.append(ThemeStr(" ",
                                   ThemeAttr("types", "iptables_comment")))
                tmp_message.append(ThemeStr(" ".join(item[j:]),
                                   ThemeAttr("types", "iptables_comment")))
                break
            else:
                tmp_message.append(ThemeStr(f" {item}",
                                   ThemeAttr("types", "iptables_argument")))

        if not i:
            new_message = tmp_message
        else:
            new_remnants.append((tmp_message, severity))

    if fold_msg and "\\n" in message:
        for remnant, _severity in new_remnants:
            new_message.append(ThemeRef("separators", "newline"))
            new_message += remnant

        new_remnants = []
    return facility, severity, new_message, new_remnants
