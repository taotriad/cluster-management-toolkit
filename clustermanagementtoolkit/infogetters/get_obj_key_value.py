# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to get key/value data.
"""

import re
from typing import Any, Literal

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.infogetters.transform_filter import transform_filter
from clustermanagementtoolkit.infogetters.when_filter import when_filter


# pylint: disable-next=too-many-branches,too-many-statements,too-many-locals
def get_obj_key_value(obj: dict, path: list[DictPath], ipath: dict,
                      values: list[Any], **kwargs: Any) -> list[Any]:
    """
    A helper for get_obj() that extracts key/value data.

        Parameters:
            obj (dict): The object to extract data from
            path ([DictPath]): A path with fallbacks
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
            **kwargs (dict[str, Any]): Keyword arguments
                default (Any): The value to return if no matches are found
                vtype (str): The value type
        Returns:
            ([Any]):
                ([Any]): A list of objects
    """
    default = deep_get(kwargs, DictPath("default"))
    vtype = deep_get(kwargs, DictPath("vtype"))

    value = []
    tmp = deep_get_with_fallback(obj, path, {})
    subtype: Literal["dict", "strlist"] = deep_get(ipath, DictPath("subtype"), "dict")
    # This is to be for key_value-lists provided as strings
    if subtype == "strlist" and isinstance(tmp, str):
        strlist = {}
        for kv in tmp.split(","):
            kv_tuple = kv.split("=")
            if len(kv_tuple) != 2:
                break
            strlist[kv_tuple[0]] = kv_tuple[1]
            tmp = strlist
    if isinstance(tmp, list):
        tmp2: dict[str, Any] = {}
        for item in tmp:
            if not isinstance(item, dict):
                break
            tmp2 = {**tmp2, **item}
        tmp = tmp2
    for _key, _value in tmp.items():
        subpaths = deep_get(ipath, DictPath("subpaths"), [])
        if subpaths:
            _value = deep_get_with_fallback(_value, subpaths)
        if not when_filter(ipath, item={}, key=_key, value=_value):
            continue
        _regexes_key = deep_get(ipath, DictPath("key#regex"), [])
        _regexes_value = deep_get(ipath, DictPath("value#regex"), [])
        if isinstance(_regexes_key, str):
            _regexes_key = [_regexes_key]
        if isinstance(_regexes_value, str):
            _regexes_value = [_regexes_value]
        _key = transform_filter(_key,
                                deep_get(ipath, DictPath("key#transform"), {}))
        _value = transform_filter(_value,
                                  deep_get(ipath, DictPath("value#transform"), {}))
        # A regex for key/value is required to capture only one group;
        # (though conceivably there might be scenario for joining),
        # thus the first non-None capture group will exit the match;
        # when using multiple regexes the first matching regex exits
        match = False
        for _regex in _regexes_key:
            if (re_tmp := re.match(_regex, _key)) is None:
                continue

            for group in re_tmp.groups():
                if group is not None:
                    _key = group
                    match = True
            if match:
                break
        match = False
        for _regex in _regexes_value:
            if (re_tmp := re.match(_regex, _value)) is None:
                continue

            for group in re_tmp.groups():
                if group is not None:
                    _value = group
                    match = True
            if match:
                break
        # A transform might yield multiple identical key/value pairs;
        # ignore all except the first one
        if (_key, _value) in value:
            continue
        value.append((_key, _value))
    if not value:
        if default is None:
            value = []
        else:
            value = default
    for tmp in value:
        values.append((tmp, vtype))
    return values
