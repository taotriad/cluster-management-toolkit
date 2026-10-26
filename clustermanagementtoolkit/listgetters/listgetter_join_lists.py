# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list created by joining multiple lists into one.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


def listgetter_join_lists(obj: dict[str, Any], **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    A listgetter that takes two or more lists and joins them into one list.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments
                paths ([str]): A list of paths to the lists to join.
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list of objects
                (int): The status for the request
    """
    paths = deep_get(kwargs, DictPath("paths"))
    vlist = []

    for path in paths:
        name_key = deep_get(path, DictPath("name_key"), "")
        name_value = deep_get(path, DictPath("name_value"), "")
        list_path = deep_get(path, DictPath("path"), [])
        d = {}
        if name_key:
            d[name_key] = name_value
        for key, value in deep_get_with_fallback(obj, list_path, []).items():
            d[key] = value
        vlist.append(d)
    return vlist, 200
