# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of dicts joined into lists.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# key_paths: the dict keys that should be turned into values
# key_name: name for the key that holds these values
# fields: paths the fields in the dict that should be added to the list
#
# Thus:
# "a": {
#     "b": {
#        "d": 1,
#        "e": 2
#     },
#     "c": {
#        "d": 2,
#        "e": 3,
#     },
# }
# key_paths = ["a#b", "a#c"]
# key_name = "foo"
# fields = [{"path": "a#b", "name": "bar"}, {"path": "a#c", "name": "baz"}]
# would generate the list
# [{"foo": "d", "bar": 1, "baz": 2}, {"foo": "e", "bar": 2, "baz": 3}]
def listgetter_join_dicts_to_list(obj: dict[str, Any],
                                  **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Join dicts into a single list.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments
                key_paths (str): The paths to join paths from
                key_name (str): The name to give to the key field
                fields ([dict[str, str]]): A list of dict paths, and the names to give them
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list representation of the dicts
                (int): The status for the request
    """
    vlist: list[dict[str, Any]] = []
    key_paths: list[str] = deep_get(kwargs, DictPath("key_paths"), [])
    key_name: str = deep_get(kwargs, DictPath("key_name"), "key")
    fields: list[dict[Any, Any]] = deep_get(kwargs, DictPath("fields"), [])

    keys = set()

    for key_path in key_paths:
        for key in deep_get(obj, DictPath(key_path), {}):
            keys.add(key)

    for key in keys:
        d = {
            key_name: key
        }
        for field in fields:
            path = deep_get(field, DictPath("path"), "")
            if (name := deep_get(field, DictPath("name"))) is None:
                continue
            value = deep_get(obj, DictPath(f"{path}#{key}"))
            d[name] = value
        if len(d) <= 1:
            continue
        vlist.append(d)
    return vlist, 200
