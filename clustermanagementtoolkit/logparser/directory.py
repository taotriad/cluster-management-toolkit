# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def directory(message: str,
              **kwargs: Any) -> tuple[str, LogLevel,
                                      str | list[ThemeRef | ThemeStr],
                                      list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Format the output from "ls -alF --color" command.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ((str, LogLevel, str|ThemeArray, [(ThemeArray, LogLevel)]))):
                (str): The log facility
                (LogLevel): The LogLevel of the message
                (str|ThemeArray): The unchanged message if nothing matched,
                                  or the formatted themearray
                ([(ThemeArray, LogLevel)]): [unused]
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")

    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

    if (re_tmp := re.match(r"^(total)\s+(\d+)$", message)) is not None:
        return facility, severity, message, remnants

    re_tmp = re.match(r"^(.)"                  # etype
                      r"(.{9})"                # permissions
                      r"(\+|\s)"               # acl
                      r"(\s+)"                 # space1
                      r"(\d+)"                 # linkcount
                      r"(\s+)"                 # space2
                      r"([^\s]+)"              # owner
                      r"(\s+)"                 # space3
                      r"([^\s]+)"              # group
                      r"(\s+)"                 # space4
                      r"(\d+)"                 # size part1
                      r"(,\s+\d+|)"            # size part2
                      r"(\s+)"                 # space5
                      r"([^\s]+)"              # month
                      r"(\s+)"                 # space6
                      r"(\d+)"                 # day
                      r"(\s+)"                 # space7
                      r"([^\s]+)"              # yearortime
                      r"(\s+)"                 # space8
                      r"(.+?)"                 # name
                      r"(=|\||/|)$", message)  # suffix
    if re_tmp is None:
        # This is unlikely to be a directory match
        return facility, severity, message, remnants

    etype = re_tmp[1]
    permissions = re_tmp[2]
    acl = re_tmp[3]
    space1 = re_tmp[4]
    linkcount = re_tmp[5]
    space2 = re_tmp[6]
    owner = re_tmp[7]
    space3 = re_tmp[8]
    group = re_tmp[9]
    space4 = re_tmp[10]
    size = re_tmp[11] + re_tmp[12]
    space5 = re_tmp[13]
    month = re_tmp[14]
    space6 = re_tmp[15]
    day = re_tmp[16]
    space7 = re_tmp[17]
    yearortime = re_tmp[18]
    space8 = re_tmp[19]
    name = re_tmp[20]
    suffix = re_tmp[21]

    _message: list[ThemeRef | ThemeStr] = [
        ThemeStr(f"{etype}", ThemeAttr("types", "dir_type")),
        ThemeStr(f"{permissions}", ThemeAttr("types", "dir_permissions")),
        ThemeStr(f"{acl}", ThemeAttr("types", "dir_permissions")),
        ThemeStr(f"{space1}", ThemeAttr("types", "generic")),
        ThemeStr(f"{linkcount}", ThemeAttr("types", "dir_linkcount")),
        ThemeStr(f"{space2}", ThemeAttr("types", "generic")),
        ThemeStr(f"{owner}", ThemeAttr("types", "dir_owner")),
        ThemeStr(f"{space3}", ThemeAttr("types", "generic")),
        ThemeStr(f"{group}", ThemeAttr("types", "dir_group")),
        ThemeStr(f"{space4}", ThemeAttr("types", "generic")),
        ThemeStr(f"{size}", ThemeAttr("types", "dir_size")),
        ThemeStr(f"{space5}", ThemeAttr("types", "generic")),
        ThemeStr(f"{month}", ThemeAttr("types", "dir_date")),
        ThemeStr(f"{space6}", ThemeAttr("types", "generic")),
        ThemeStr(f"{day}", ThemeAttr("types", "dir_date")),
        ThemeStr(f"{space7}", ThemeAttr("types", "generic")),
        ThemeStr(f"{yearortime}", ThemeAttr("types", "dir_date")),
        ThemeStr(f"{space8}", ThemeAttr("types", "generic")),
    ]
    # regular file
    if etype == "-":
        _message += [
            ThemeStr(f"{name}", ThemeAttr("types", "dir_file"))
        ]
    # block or character device
    elif etype in ("b", "c"):
        _message += [
            ThemeStr(f"{name}", ThemeAttr("types", "dir_dev"))
        ]
    # sticky bit has precedence over the regular directory type
    elif permissions.endswith("t"):
        _message += [
            ThemeStr(f"{name}", ThemeAttr("types", "dir_sticky"))
        ]
    # directory
    elif etype == "d":
        _message += [
            ThemeStr(f"{name}", ThemeAttr("types", "dir_dir"))
        ]
    # symbolic link
    elif etype == "l":
        if (re_tmp := re.match(r"^(.+?)( -> )(.+)", name)) is None:
            _message += [
                ThemeStr(f"{name}", ThemeAttr("types", "dir_symlink_name"))
            ]
        else:
            _message += [
                ThemeStr(f"{re_tmp[1]}", ThemeAttr("types", "dir_symlink_name")),
                ThemeStr(f"{re_tmp[2]}", ThemeAttr("types", "dir_symlink_link"))
            ]
            # There is no suffix for devices or regular files,
            # but we can distinguish the two based on the file size;
            # the size for devices is not really a size per se,
            # but rather major, minor (a normal size never has a comma)
            if not suffix:
                if "," in size:
                    _message += [
                        ThemeStr(f"{re_tmp[3]}", ThemeAttr("types", "dir_dev")),
                    ]
                else:
                    _message += [
                        ThemeStr(f"{re_tmp[3]}", ThemeAttr("types", "dir_file")),
                    ]
            elif suffix == "|":
                _message += [
                    ThemeStr(f"{re_tmp[3]}", ThemeAttr("types", "dir_pipe")),
                ]
            elif suffix == "=":
                _message += [
                    ThemeStr(f"{re_tmp[3]}", ThemeAttr("types", "dir_socket")),
                ]
            elif suffix == "/":
                _message += [
                    ThemeStr(f"{re_tmp[3]}", ThemeAttr("types", "dir_dir")),
                ]
            else:
                errmsg = [
                    [("Unhandled suffix ", "default"),
                     (f"{suffix}", "argument"),
                     (f" in line {message}.", "default")],
                ]
                unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)

                _message += [
                    ThemeStr(f"{re_tmp[3]}", ThemeAttr("types", "dir_file")),
                ]
    # pipe
    elif etype == "p":
        _message += [
            ThemeStr(f"{name}", ThemeAttr("types", "dir_pipe"))
        ]
    # socket
    elif etype == "s":
        _message += [
            ThemeStr(f"{name}", ThemeAttr("types", "dir_socket"))
        ]

    if suffix:
        _message += [
            ThemeStr(f"{suffix}", ThemeAttr("types", "dir_suffix"))
        ]

    return facility, severity, _message, remnants
