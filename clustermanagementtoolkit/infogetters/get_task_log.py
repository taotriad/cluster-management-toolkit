# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper to get logs from Ansible tasks.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import color_status_group


# pylint: disable-next=unused-argument
def get_task_log(obj: dict, **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Get logs from Ansible tasks.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments
                log#skipped (bool): Was the log task skipped? True if the task was skipped
                log#stdout_lines (list[str]): Output to stdout
                log#stderr_lines (list[str]): Output to stderr
                log#msg_lines (list[str]): Merged output
        Returns:
            ([[ThemeRef|ThemeStr]]): A list of messages
    """
    field: list = []

    skipped = deep_get(obj, DictPath("log#skipped"), False)
    stdout_lines = deep_get(obj, DictPath("log#stdout_lines"), [])
    stderr_lines = deep_get(obj, DictPath("log#stderr_lines"), [])
    msg_lines = deep_get(obj, DictPath("log#msg_lines"), [])

    if skipped:
        field.append([ThemeStr("[skipped]", ThemeAttr("types", "unset"))])
        return field

    if stderr_lines:
        field.append([ThemeStr("stderr:", ThemeAttr("main", "paragraphheader"))])
        for line in stderr_lines:
            field.append([ThemeStr(f"{line}", color_status_group(StatusGroup.NOT_OK))])

    if stdout_lines:
        if field:
            field.append([ThemeStr("", ThemeAttr("main", "default"))])
        field.append([ThemeStr("stdout:", ThemeAttr("main", "paragraphheader"))])
        for line in stdout_lines:
            field.append([ThemeStr(f"{line}", ThemeAttr("main", "default"))])

    if msg_lines:
        if field:
            field.append([ThemeStr("", ThemeAttr("main", "default"))])
            field.append([ThemeStr("", ThemeAttr("main", "default"))])
        field.append([ThemeStr("msg:", ThemeAttr("main", "paragraphheader"))])
        for line in msg_lines:
            field.append([ThemeStr(f"{line}", color_status_group(StatusGroup.OK))])

    return field
