# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to get dict items.
"""

from typing import Any

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.infogetters.when_filter import when_filter


# pylint: disable-next=too-many-locals
def get_obj_tuple(obj: dict, path: list[DictPath], ipath: dict,
                  values: list[Any], **kwargs: Any) -> tuple[list[Any], bool]:
    """
    A helper for get_obj() to get tuples.

        Parameters:
            obj (dict): The object to extract data from
            path ([DictPath]): A path with fallbacks
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
            **kwargs (dict[str, Any]): Keyword arguments
                default (Any): The value to return if no matches are found
                fallback_on_empty (bool): Use the default vault if the list is empty?
                field_index (str): The index of the field
                view (str): The view the object is to be displayed in
                vtype (str): The value type
        Returns:
            (([Any], bool)):
                ([Any]): A list of objects
                (bool): True if the filter matched, False if the match was filtered out
                        (no data added to values)
    """
    default = deep_get(kwargs, DictPath("default"))
    fallback_on_empty = deep_get(kwargs, DictPath("fallback_on_empty"), False)
    field_index = deep_get(kwargs, DictPath("field_index"))
    view = deep_get(kwargs, DictPath("view"))
    vtype = deep_get(kwargs, DictPath("vtype"))

    value = []

    if not when_filter(ipath, item=obj):
        return values, False
    for i, element in enumerate(path):
        if isinstance(default, list):
            if i < len(default):
                _default = default[i]
            else:
                _default = None
        else:
            _default = default

        if vtype in ("int", "float") and type(default) not in (int, float):
            _default = 0

        # This is a literal string, not a path
        if isinstance(element, str):
            tmp: str = element
        else:
            tmp = deep_get_with_fallback(obj, element, default=_default,
                                         fallback_on_empty=fallback_on_empty)

        if vtype == "api_group":
            override_paths = [DictPath(f"Views#{view}#kind_format_{field_index}"),
                              DictPath(f"Views#{view}#kind_format"),
                              DictPath(f"Global#kind_format_{field_index}"),
                              DictPath("Global#kind_format")]
            override_kind = \
                deep_get_with_fallback(cmtlib.cmtconfig, override_paths, "mixed")
            if override_kind == "skip" \
                    or override_kind == "mixed" and "." not in tmp:
                tmp = ""
            vtype = "kind"
        value.append(tmp)
    if isinstance(deep_get(ipath, DictPath("substitute")), list):
        value = deep_get(ipath, DictPath("substitute"))
    values.append((tuple(value), vtype))
    return values, True
