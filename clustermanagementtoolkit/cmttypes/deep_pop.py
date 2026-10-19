# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Pop a value in a dict.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes.dictpath import DictPath
from clustermanagementtoolkit.cmttypes.deep_get import deep_get


def deep_pop(dictionary: Any | None, path: DictPath, key: DictPath, default: Any = None) -> Any:
    """
    Given a dictionary, a path into that dictionary, and a key at that path, pop the key
    and return its value (or default if the dict, path, or key doesn't exist).

    FIXME: Surely this implementation is broken?

        Parameters:
            dictionary (dict|CommentedMap): The dict to get the value from
            path (DictPath): A dict path
            key (DictPath): A dict key to pop
            default (Any): The value to return if the dictionary, path, key, or result is None
        Returns:
            (Any): The value from the path
    """
    reduced_path: dict | DictPath | None = \
        deep_get(dictionary, path, default)
    if reduced_path is not None:
        if isinstance(reduced_path, dict):
            result = reduced_path.pop(key, default)
        else:
            result = reduced_path
    else:
        result = default

    return result
