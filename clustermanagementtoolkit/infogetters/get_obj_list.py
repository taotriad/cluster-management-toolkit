# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to get key/value data.
"""

from typing import Any

from natsort import natsorted

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


def get_obj_list(obj: dict, path: list[DictPath], ipath: dict,
                 values: list[Any], **kwargs: Any) -> list[Any]:
    """
    A helper for get_obj() that extracts lists.

        Parameters:
            obj (dict): The object to extract data from
            path ([DictPath]): A path with fallbacks
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
            **kwargs (dict[str, Any]): Keyword arguments
                default (Any): The value to return if no matches are found
                fallback_on_empty (bool): Use the default vault if the list is empty?
                limit (int | None): The max number of list entries to return
                vtype (str): The value type
        Returns:
            ([Any]):
                ([Any]): A list of objects
    """
    default = deep_get(kwargs, DictPath("default"))
    fallback_on_empty = deep_get(kwargs, DictPath("fallback_on_empty"), False)
    limit = deep_get(kwargs, DictPath("limit"))
    vtype = deep_get(kwargs, DictPath("vtype"))

    tmp = deep_get_with_fallback(obj, path, default=default,
                                 fallback_on_empty=fallback_on_empty)
    if deep_get(ipath, DictPath("sorted"), False) and tmp is not None:
        tmp = natsorted(tmp)

    if tmp is not None and tmp in ("None", ["None"]) \
            and deep_get(ipath, DictPath("none_str_as_none"), False):
        tmp = default

    # Just return the list, unless a subset has been requested
    if limit is not None and tmp is not None:
        value = tmp[0:limit]
    else:
        value = tmp

    values.append((value, vtype))
    return values
