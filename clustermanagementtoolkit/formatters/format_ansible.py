# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Ansible formatter; formats output from Ansible plays; this formatter
does NOT use Pygments, since the Pygments lexer was deemed inferior.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmtlib import split_msg

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


# pylint: disable-next=too-many-locals,too-many-branches,unused-argument
def format_ansible(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Ansible formatter; formats output from Ansible plays.
    Note: The Pygments lexer for Ansible has been tested, but found, at least currently,
    not fit for the purpose of replacing this formatter.

        Parameters:
            lines ([str]): A list of strings
            *or*
            lines (str): a string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([themearray]): A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []
    recap_flag: bool = False

    if isinstance(lines, str):
        lines = split_msg(lines)

    for line in lines:
        fmt: ThemeAttr | None = None

        if line.startswith("No config file found; using defaults"):
            fmt = ThemeAttr("logview", "severity_debug")
        elif line.startswith("[WARNING]: "):
            fmt = ThemeAttr("logview", "severity_warning")
        elif line.startswith(("[ERROR]: ", "fatal: ")):
            fmt = ThemeAttr("logview", "severity_error")
        elif line.startswith("ok: "):
            fmt = ThemeAttr("main", "status_ok")
        elif line.startswith("skipping: "):
            fmt = ThemeAttr("main", "status_ignored")
        elif line.startswith("PLAY RECAP "):
            fmt = ThemeAttr("types", "generic")
            recap_flag = True

        if not recap_flag and not fmt:
            fmt = ThemeAttr("types", "generic")

        if fmt:
            dumps.append([ThemeStr(line, fmt)])
            continue

        tmp = re.match(r"(\S+)(\s+: )(ok=)(\d+)(\s+)(changed=)(\d+)(\s+)"
                       r"(unreachable=)(\d+)(\s+)"
                       r"(failed=)(\d+)(\s+)(skipped=)(\d+)(\s+)"
                       r"(rescued=)(\d+)(\s+)(ignored=)(\d+)", line)
        if not tmp:
            fmt = ThemeAttr("types", "generic")
            dumps.append([ThemeStr(line, fmt)])
            continue

        hostname, ws1, ok, okcount, ws2, changed, changedcount, ws3, unreachable, \
            unreachablecount, ws4, failed, failedcount, ws5, skipped, skippedcount, \
            ws6, rescued, rescuedcount, ws7, ignored, ignoredcount = tmp.groups()

        try:
            if int(failedcount) or int(unreachablecount):
                fmt = ThemeAttr("logview", "severity_error")
            elif int(rescuedcount):
                fmt = ThemeAttr("main", "status_warning")
            elif int(changedcount):
                fmt = ThemeAttr("main", "status_pending")
            elif int(skippedcount) or int(ignoredcount):
                fmt = ThemeAttr("main", "status_ignored")
            elif int(okcount):
                fmt = ThemeAttr("main", "status_ok")
            else:
                fmt = ThemeAttr("types", "generic")
        except ValueError:
            fmt = ThemeAttr("main", "status_attention")

        dumps.append([ThemeStr(hostname, fmt),                                      # hostname
                      ThemeStr(ws1, ThemeAttr("types", "generic")),                 # whitespace
                      ThemeStr(ok, ThemeAttr("main", "status_ok")),                 # ok=
                      ThemeStr(okcount, ThemeAttr("types", "numerical")),           # count
                      ThemeStr(ws2, ThemeAttr("types", "generic")),                 # whitespace
                      ThemeStr(changed, ThemeAttr("main", "status_pending")),       # changed=
                      ThemeStr(changedcount, ThemeAttr("types", "numerical")),      # count
                      ThemeStr(ws3, ThemeAttr("types", "generic")),                 # whitespace
                      ThemeStr(unreachable, ThemeAttr("main", "status_warning")),   # unreachable=
                      ThemeStr(unreachablecount, ThemeAttr("types", "numerical")),  # count
                      ThemeStr(ws4, ThemeAttr("types", "generic")),                 # whitespace
                      ThemeStr(failed, ThemeAttr("main", "status_not_ok")),         # failed=
                      ThemeStr(failedcount, ThemeAttr("types", "numerical")),       # count
                      ThemeStr(ws5, ThemeAttr("types", "generic")),                 # whitespace
                      ThemeStr(skipped, ThemeAttr("main", "status_ignored")),       # skipped=
                      ThemeStr(skippedcount, ThemeAttr("types", "numerical")),      # count
                      ThemeStr(ws6, ThemeAttr("types", "generic")),                 # whitespace
                      ThemeStr(rescued, ThemeAttr("main", "status_warning")),       # rescued=
                      ThemeStr(rescuedcount, ThemeAttr("types", "numerical")),      # count
                      ThemeStr(ws7, ThemeAttr("types", "generic")),                 # whitespace
                      ThemeStr(ignored, ThemeAttr("main", "status_ignored")),       # ignored=
                      ThemeStr(ignoredcount, ThemeAttr("types", "numerical"))])     # count
    return dumps
