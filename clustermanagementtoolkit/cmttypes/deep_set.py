# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Set a value in a dict.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes.dictpath import DictPath
from clustermanagementtoolkit.cmttypes.deep_get import deep_get


def deep_set(dictionary: Any, path: DictPath, value: Any, create_path: bool = False) -> None:
    """
    Given a dictionary, a path into that dictionary, and a value, set the path to that value.

        Parameters:
            dictionary (dict): The dict to set the value in
            path (DictPath): A dict path
            value (any): The value to set
            create_path (bool): If True the path will be created if it does not exist
    """
    if dictionary is None or path is None or not path:
        raise ValueError(f"deep_set: dictionary {dictionary} or path {path} invalid/unset")

    ref = dictionary
    pathsplit = path.split("#")

    for i, pathsegment in enumerate(pathsplit):  # pragma: no branch
        # Note that we're (potentially) updating ref every iteration
        if ref is None or not isinstance(ref, dict):
            raise ValueError(f"Path {path} does not exist in dictionary {dictionary} "
                             f"or is the wrong type {type(ref)}")

        if (pathsegment not in ref or ref[pathsegment] is None) and create_path:
            ref[pathsegment] = {}

        if i == len(pathsplit) - 1:
            ref[pathsegment] = value
            break

        ref = deep_get(ref, DictPath(pathsegment))
