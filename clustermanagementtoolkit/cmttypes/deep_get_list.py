# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return all values in a dict from a list of paths in that dict.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes.dictpath import DictPath
from clustermanagementtoolkit.cmttypes.deep_get import deep_get


def __deep_get_recursive(dictionary: dict,
                         path_fragments: list[str],
                         result: list | None = None) -> list[Any] | None:
    if result is None:
        result = []

    for i, path_fragment in enumerate(path_fragments):  # pragma: no branch
        tmp = deep_get(dictionary, DictPath(path_fragment))
        if i + 1 == len(path_fragments):
            if tmp is None:
                return result
            return tmp

        if isinstance(tmp, dict):
            return __deep_get_recursive(tmp, path_fragments[i + 1:len(path_fragments)], result)
        if isinstance(tmp, list):  # pragma: no branch
            result = []
            for tmp2 in tmp:
                result.append(__deep_get_recursive(tmp2,
                                                   path_fragments[i + 1:len(path_fragments)],
                                                   result))

    return result


def deep_get_list(dictionary: Any,
                  paths: list[DictPath],
                  default: list[Any] | None = None,
                  fallback_on_empty: bool = False) -> list[Any] | None:
    """
    Given a dictionary and a list of paths into that dictionary, get all values.

        Parameters:
            dictionary (dict): The dict to get the values from
            path ([DictPath]): A list of dict paths
            default ([Any]): The value to return if the dictionary, paths, or results are None
            fallback_on_empty (bool): Should "" be treated as None?
        Returns:
            ([Any]): The values from the paths
    """
    if dictionary is None or paths is None:
        return default

    result = None
    for path in paths:
        if path is None:
            continue
        result = __deep_get_recursive(dictionary, path.split("#"))

        if (result is not None and not
                (type(result) in (list, str, dict) and not result and fallback_on_empty)):
            break
    if result is None or type(result) in (list, str, dict) and not result and fallback_on_empty:
        result = default
    return result
