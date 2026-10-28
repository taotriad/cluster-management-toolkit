# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to get dict items.
"""

import re
from typing import Any, Literal

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_list
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.infogetters.__process_string import __process_string
from clustermanagementtoolkit.infogetters.transform_filter import transform_filter
from clustermanagementtoolkit.infogetters.when_filter import when_filter


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_obj_items(obj: dict, mpaths: list[list[DictPath]], ipath: dict,
                  values: list[Any], **kwargs: Any) -> list[Any]:
    """
    A helper for get_obj() to get dict items.

        Parameters:
            obj (dict): The object to extract data from
            mpaths ([[DictPath]]): Multiple paths to iterate over
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
            **kwargs (dict[str, Any]): Keyword arguments
                action (str): An action to perform on the data; can be one of:
                              sum, latest, earliest
                default (Any): The value to return if no matches are found
                fallback_on_empty (bool): Use the default vault if the list is empty?
                limit (int | None): The max number of list entries to return
                pathtype (str): The path type
                subpaths (str): The subpaths of the items to get
                vtype (str): The value type
        Returns:
            ([Any]):
                ([Any]): A list of objects
    """
    action: Literal["earliest", "latest", "sum", ""] = deep_get(kwargs, DictPath("action"), "")
    default = deep_get(kwargs, DictPath("default"))
    fallback_on_empty = deep_get(kwargs, DictPath("fallback_on_empty"), False)
    limit = deep_get(kwargs, DictPath("limit"))
    pathtype = deep_get(kwargs, DictPath("pathtype"))
    subpaths = deep_get(kwargs, DictPath("subpaths"))
    vtype = deep_get(kwargs, DictPath("vtype"))

    value: Any = []
    items: list[Any] = []
    index = deep_get(ipath, DictPath("index"))
    for mpath in mpaths:
        if isinstance(mpath, str):
            mpath = [mpath]
        tmp = deep_get_list(obj, mpath, default=[],
                            fallback_on_empty=fallback_on_empty)
        if tmp is not None and index is not None:
            try:
                tmp = [tmp[index]]
            except IndexError:
                pass
        # XXX: This is to avoid breaking anything
        # Ideally the "appenditems" behaviour should be the only one,
        # but requires rewriting a lot of files
        if pathtype == "items" and tmp is not None:
            items += tmp
        else:
            items.append(tmp)

    # pylint: disable-next=too-many-nested-blocks
    for item in items:
        if not when_filter(ipath, item):
            continue

        tmp = []
        for i, subpath in enumerate(subpaths):
            if isinstance(default, list):
                if i < len(default):
                    _default = default[i]
                else:
                    _default = None
            else:
                _default = default

            if (vtype in ("int", "float") or action in ["sum"]) \
                    and type(default) not in (int, float):
                _default = 0

            if isinstance(subpath, dict):
                _subpath = deep_get(subpath, DictPath("str"))
                if _subpath is not None:
                    tmp.append(_subpath)
                else:
                    _subpath = deep_get(subpath, DictPath("subpath"))
                    _default = deep_get(subpath, DictPath("default"), _default)
                    _fallback_path = deep_get(subpath, DictPath("fallback_path"))
                    _fallback_value = deep_get(obj, DictPath(_fallback_path))
                    if _fallback_value is not None and _default is None:
                        _default = _fallback_value
                    if isinstance(_subpath, str):
                        _subpath = [_subpath]
                    _regexes = deep_get(subpath, DictPath("regex"), [])
                    if isinstance(_regexes, str):
                        _regexes = [_regexes]
                    _raw = deep_get_with_fallback(item, _subpath, _default)
                    _raw = transform_filter(_raw, deep_get(subpath, DictPath("transform"), {}))
                    for _regex in _regexes:
                        if (re_tmp := re.match(_regex, _raw)) is not None:
                            for group in re_tmp.groups():
                                if group is not None:
                                    tmp.append(group)
                            break
                        tmp.append("")
                    if not tmp or not _regexes:
                        tmp.append(_raw)
            else:
                prefix = deep_get(ipath, DictPath("prefix"), [])
                suffix = deep_get(ipath, DictPath("suffix"), [])
                regex_ = deep_get(ipath, DictPath("regex"))
                _subpath = subpath
                if isinstance(_subpath, str):
                    _subpath = [_subpath]
                tmp_ = deep_get_with_fallback(item, _subpath, _default)
                if isinstance(tmp_, str):
                    if regex_:
                        if (re_tmp := re.match(regex_, tmp_)) is not None:
                            tmp_ = []
                            for group in re_tmp.groups():
                                if group is not None:
                                    tmp_.append(group)
                            if len(tmp_) > 1:
                                tmp_ = tuple(tmp_)
                        elif fallback_on_empty:
                            tmp_ = _default
                    else:
                        tmp_ = __process_string(tmp_, quotes="same")
                if isinstance(prefix, str):
                    if isinstance(tmp_, str):
                        tmp_ = prefix + tmp_
                    else:
                        tmp_ = [prefix] + tmp_
                else:
                    tmp += prefix

                if isinstance(suffix, str):
                    if isinstance(tmp_, str):
                        tmp_ += suffix
                    else:
                        tmp_ += [suffix]

                tmp.append(tmp_)

                if isinstance(suffix, list):
                    tmp += suffix
        if not limit or len(value) < limit:
            if len(tmp) == 1:
                value.append(tmp[0])
            else:
                value.append(tuple(tmp))
    if not value:
        value = default
    if value is not None:
        if action in ("sum", "latest", "earliest"):
            values.append((value, vtype))
        else:
            for tmp in value:
                values.append((tmp, vtype))
    return values
