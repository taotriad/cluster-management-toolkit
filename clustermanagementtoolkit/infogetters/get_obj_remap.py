# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to remap strings.
"""
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.infogetters.when_filter import when_filter


# pylint: disable-next=too-many-branches
def get_obj_remap(obj: dict, path: list[DictPath], ipath: dict,
                  values: list[Any], **kwargs: Any) -> tuple[list[Any], bool]:
    """
    A helper for get_obj() that remaps strings.

        Parameters:
            obj (dict): The object to extract data from
            path ([DictPath]): A path with fallbacks
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
            **kwargs (dict[str, Any]): Keyword arguments
                default (Any): The value to return if no matches are found
                substitutions (dict[str, str]): A dict of string substitutions
                vtype (str): The value type
        Returns:
            ([Any]):
                ([Any]): A list of objects
                (bool): True on match, False on failure
    """
    default = deep_get(kwargs, DictPath("default"))
    substitutions = deep_get(ipath, DictPath("substitutions"), "")
    vtype = deep_get(kwargs, DictPath("vtype"))

    value = []

    if not when_filter(ipath, item=obj):
        if default is not None:
            value.append(default)
        values.append((value, vtype))
        return values, True

    tmp = deep_get_with_fallback(obj, path, [])

    if type(tmp) in (bool, int, str):
        tmp = [tmp]

    if isinstance(tmp, list):
        for _tmp in tmp:
            if isinstance(_tmp, bool):
                _tmp = f"__{_tmp!s}"

            if _tmp in substitutions:
                value.append(substitutions.get(_tmp))
            elif "__default" in substitutions:
                value.append(substitutions.get("__default"))
            else:
                value.append(_tmp)
    else:
        raise TypeError(f"remap is not supported yet for type {type(tmp)}")

    if not value:
        if default is None:
            return values, False
        value.append(default)

    for tmp in value:
        values.append((tmp, vtype))

    return values, True
