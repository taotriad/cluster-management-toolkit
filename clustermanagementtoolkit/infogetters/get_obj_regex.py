# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to extract data using regular expressions.
"""
import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


def get_obj_regex(obj: dict, path: list[DictPath], ipath: dict,
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
        Returns:
            ([Any]):
                ([Any]): A list of objects
    """
    default = deep_get(kwargs, DictPath("default"))

    value = []
    raw = deep_get_with_fallback(obj, path, "")
    regexes = deep_get(ipath, DictPath("regex"), [])
    findalls = deep_get(ipath, DictPath("findall"), [])

    if isinstance(regexes, str):
        regexes = [regexes]

    if isinstance(findalls, str):
        findalls = [findalls]

    if raw is not None and raw:
        for regex in regexes:
            if (re_tmp := re.match(regex, raw)) is not None:
                for group in re_tmp.groups():
                    if group is not None:
                        value.append(group)
                break
        for findall in findalls:
            if (fa_tmp := re.findall(findall, raw)) is not None:
                value += fa_tmp
                break
    elif default:
        value = default

    values.append((tuple(value), "raw"))

    return values
