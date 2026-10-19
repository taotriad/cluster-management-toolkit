# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a value from path into a dict from the first path that has a value.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes.dictpath import DictPath
from clustermanagementtoolkit.cmttypes.deep_get import deep_get


def deep_get_with_fallback(obj: Any,
                           paths: list[DictPath],
                           default: Any | None = None, fallback_on_empty: bool = False) -> Any:
    """
    Given a dictionary and a list of paths into that dictionary,
    get the value from the first path that has a value.

        Parameters:
            dictionary (dict): The dict to get the value from
            paths ([DictPath]): A list of dict paths
            default (any): The value to return if the dictionary, path or result is None
            fallback_on_empty (bool): Should "" be treated as None?
        Returns:
            (Any): The value from the path(s)
    """
    if paths is None or not isinstance(paths, list):
        return default

    result = None
    for path in paths:
        result = deep_get(obj, path)
        if (result is not None and not
                (type(result) in (list, str, dict) and not result and fallback_on_empty)):
            break
    if result is None or type(result) in (list, str, dict) and not result and fallback_on_empty:
        result = default
    return result
