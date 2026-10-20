# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that splits a string with embedded newlines into multiple lines.
"""

from typing import Any
import yaml

from clustermanagementtoolkit.cmtlib import split_msg

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_strings_from_string(obj: dict, **kwargs: Any) -> list[list[str]]:
    """
    Get a list of strings from a string with embedded newlines.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the string
                unescape_newlines (bool): If the message contains escaped newlines,
                                          unescape them before splitting the string
                yaml_dump (bool): Should the string be formatted using yaml.dump()
        Returns:
            ([[str]]): A list of lists of strings
    """
    vlist = []
    path: DictPath = DictPath(deep_get(kwargs, DictPath("path"), ""))
    unescape_newlines: bool = deep_get(kwargs, DictPath("unescape_newlines"), False)
    yaml_dump: bool = deep_get(kwargs, DictPath("yaml_dump"), False)
    tmp = deep_get(obj, DictPath(path), "")

    if yaml_dump:
        tmp = yaml.dump(tmp, indent=0, default_style=">")
        # Now we need to strip the scalar.
        tmp = tmp.removeprefix(">-\n")

    if tmp is not None and tmp:
        if unescape_newlines:
            tmp = tmp.replace("\\n", "\n")
        for line in split_msg(tmp):
            if yaml_dump and line.startswith("  "):
                line = line[2:]
            vlist.append([line])
    return vlist
