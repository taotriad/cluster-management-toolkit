# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return tuples from a dict.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes.dictpath import DictPath
from clustermanagementtoolkit.cmttypes.deep_get_with_fallback import deep_get_with_fallback


def deep_get_str_tuple_paths(obj: Any,
                             paths: list[str | list[DictPath]],
                             default: str = "", fallback_on_empty: bool = False) -> str:
    """
    Given a dictionary and a list of strings or paths into that dictionary,
    get the value from each path and joined them together with the verbatim strings,
    with special consideration taken for apiFamily/apiVersion (remove the version).

        Parameters:
            dictionary (dict): The dict to get the value from
            paths ([DictPath]): A list of dict paths or verbatim strings
            default (any): The value to return if the dictionary, path or result is None
            fallback_on_empty (bool): Should "" be treated as None?
        Returns:
            (str): The joined string
    """
    string: str = ""
    prev: list | str = ""

    for fragment in paths:
        # This isn't a path, it's a verbatim string
        if isinstance(fragment, str):
            string += fragment
        elif isinstance(fragment, list):
            tmp_string = deep_get_with_fallback(obj, fragment, "")
            if fragment in (["apiFamily"], ["apiVersion"]) and prev == ["kind"]:
                if "/" in tmp_string:
                    string += "." + tmp_string.split("/", maxsplit=1)[0]
            else:
                string += tmp_string
        else:
            raise TypeError("deep_get_str_tuple_paths() called with invalid path segment: "
                            f"{fragment}")
        prev = fragment
    if fallback_on_empty and not string:
        string = default
    return string
