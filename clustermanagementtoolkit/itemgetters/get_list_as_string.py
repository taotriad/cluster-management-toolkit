# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_list_as_string(obj: dict, **kwargs: Any) -> list[tuple[str]]:
    """
    Merge all elements of a list into a single string.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the list
                separators ([str]): The separator(s) to insert between list elements;
                                    if the list is longer than the number of separators
                                    the last separator will repeat
        Returns:
            ([tuple[str]]): A list with a single one-element tuple
    """
    dest_string: str = ""
    path: str = deep_get(kwargs, DictPath("path"), "")
    separators: list[str] = deep_get(kwargs, DictPath("separators"), [])

    for i, string in enumerate(deep_get(obj, DictPath(path), [])):
        if i > 0 and separators:
            dest_string += separators[min(len(separators) - 1, i - 1)]
        dest_string += string

    if dest_string:
        return [(dest_string,)]
    return []
