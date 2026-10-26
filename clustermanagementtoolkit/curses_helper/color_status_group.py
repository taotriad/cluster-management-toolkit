# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the ThemeAttr matching a status group.
"""

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import stgroup_mapping

from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr


def color_status_group(status_group: StatusGroup) -> ThemeAttr:
    """
    Given status group, returns the corresponding ThemeAttr.

        Parameters:
            severity (LogLevel): The status group
        Returns:
            (ThemeAttr): The corresponding ThemeAttr
    """
    try:
        return ThemeAttr("main", stgroup_mapping[status_group])
    except KeyError:
        errmsg = [
            [("color_status_group()", "emphasis"),
             (" called with invalid argument(s):", "error")],
            [("status_group = ", "default"),
             (f"{status_group}", "argument"),
             (" (type: ", "default"),
             (f"{type(status_group)}", "argument"),
             (", expected: ", "default"),
             (f"{StatusGroup!r}", "argument"),
             (")", "default")],
            [("Defaulting to: ", "default"),
             (f"{StatusGroup.UNKNOWN!r}", "argument")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        return ThemeAttr("main", stgroup_mapping[StatusGroup.UNKNOWN])
