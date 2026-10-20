# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A logpad for formatted data.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters import formatter_allowlist


def logpad_formatted(obj: dict, **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Takes an object and dumps it using the specified format (if possible).

        Parameters:
            obj (dict): The dict to dump
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to get the data from
                paths ([str]): Paths in order of preference; first non-empty path will be used;
                               if merge_paths is passed the data will instead be used to form
                               a new object that contains the data from all paths
                merge_paths (bool):  True to merge multiple paths into one object
                formatter (str): The formatter to use for formatting the message
        Returns:
            ([[ThemeRef|ThemeStr]]): A list of messages
    """
    paths: list[DictPath] = deep_get(kwargs, DictPath("paths"), [])
    path: DictPath = DictPath(deep_get(kwargs, DictPath("path"), ""))
    merge_paths: bool = deep_get(kwargs, DictPath("merge_paths"), False)
    dump_formatter_tmp = deep_get(kwargs, DictPath("formatter"), "format_none")
    formatter_args = deep_get(kwargs, DictPath("formatter_args"), {})
    dump_formatter = deep_get(formatter_allowlist, DictPath(dump_formatter_tmp))
    if dump_formatter is None:
        raise ValueError(f"{dump_formatter_tmp} is not a valid formatter; "
                         "the view-file is probably incorrect.")

    newobj = {}

    if paths:
        for tmp in paths:
            tmppath = deep_get(tmp, DictPath("path"))
            tmpname = deep_get(tmp, DictPath("name"), tmppath)
            if (tmpdata := deep_get(obj, DictPath(tmppath))):
                if merge_paths:
                    newobj[tmpname] = tmpdata
                else:
                    path = tmppath
                    break

    if path:
        data = deep_get(obj, DictPath(path), "")
    elif merge_paths:
        data = newobj
    else:
        data = obj

    return dump_formatter(data, raw=deep_get(kwargs, DictPath("_show_raw"), False),
                          **formatter_args)
