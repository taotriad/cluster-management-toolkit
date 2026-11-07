# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a value from a path into a dict, with support for nesting both dicts and lists.
"""

import copy
from typing import Any

from clustermanagementtoolkit.cmttypes.dictpath import DictPath


# Keep this first so we can use it in the exceptions
def deeper_get(dictionary: Any | None, path: DictPath | None, default: Any = None) -> Any:
    """
    Given a dictionary and a path into that dictionary, get the value,
    with support for list lookups.

        Parameters:
            dictionary (dict|CommentedMap): The dict to get the value from
            path (DictPath): A dict path
            default (Any): The value to return if the dictionary, path, or result is None
        Returns:
            (Any): The value from the path
    """
    if dictionary is None:
        return default
    if path is None or not path or not isinstance(path, str):
        return default
    result = default
    d = copy.deepcopy(dictionary)
    parent: dict = {}
    parent_key: str = ""

    for key in path.split("#"):
        if isinstance(d, dict):
            parent = d
            parent_key = key
            d = d.get(key)
            result = d
            continue
        if isinstance(d, list):
            try:
                d = parent.get(parent_key)[int(key)]  # type: ignore[index]
                result = d
                continue
            except ValueError:
                pass
        result = d
        break

    if result is None:
        result = default
    return result
