# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a value from a path into a dict.
"""

from functools import reduce
from typing import Any

from clustermanagementtoolkit.cmttypes.dictpath import DictPath


# Keep this first so we can use it in the exceptions
def deep_get(dictionary: Any | None, path: DictPath | None, default: Any = None) -> Any:
    """
    Given a dictionary and a path into that dictionary, get the value.

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
    result = reduce(lambda d,
                    key: d.get(key, default) if isinstance(d, dict) else default,
                    path.split("#"), dictionary)
    if result is None:
        result = default
    return result
