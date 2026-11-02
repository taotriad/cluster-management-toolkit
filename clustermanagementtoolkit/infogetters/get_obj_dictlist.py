# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to get dictlists.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.infogetters.transform_list import transform_list


def get_obj_dictlist(obj: dict, path: list[DictPath], ipath: dict,
                     values: list[Any], **kwargs: Any) -> list[Any]:
    """
    A helper for get_obj() that extracts dict-lists.

        Parameters:
            obj (dict): The object to extract data from
            path ([DictPath]): A path with fallbacks
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
            **kwargs (dict[str, Any]): Keyword arguments
                default (Any): The value to return if no matches are found
                fallback_on_empty (bool): Use the default vault if the list is empty?
                vtype (str): The value type
        Returns:
            ([Any]):
                ([Any]): A list of objects
    """
    default = deep_get(kwargs, DictPath("default"))
    fallback_on_empty = deep_get(kwargs, DictPath("fallback_on_empty"), False)
    transform = deep_get(ipath, DictPath("transform"), {})
    vtype = deep_get(kwargs, DictPath("vtype"))

    raw = deep_get_with_fallback(obj, path, default=default,
                                 fallback_on_empty=fallback_on_empty)

    if raw is not None:
        for tmp in transform_list(raw, transform=transform):
            values.append((tmp, vtype))

    return values
