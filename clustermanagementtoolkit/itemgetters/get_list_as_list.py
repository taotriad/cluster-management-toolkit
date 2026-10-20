# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that takes a list or a list of lists and returns them as list elements.
If multiple lists are given they are returned as columns.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


# pylint: disable-next=too-many-branches,too-many-locals
def get_list_as_list(obj: dict, **kwargs: Any) -> list[Any]:
    """
    Get data in list format; if multiple lists are provided
    each list will be treated as a separate column;
    unless named_lists=True, in which case they'll be iteratively added.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the list
                paths (str): The path to the list
                named_lists (bool): If multiple paths are provided, should they be columns
                                    or named elements in one single column?
        Returns:
            ([dict]): A list of data
    """
    vlist: list[Any] = []
    # pylint: disable-next=too-many-nested-blocks
    if "path" in kwargs:
        index_template = deep_get(kwargs, DictPath("index_template"))
        raw_path = deep_get(kwargs, DictPath("path"))
        if isinstance(raw_path, str):
            raw_path = [raw_path]
        paths = []
        for path in raw_path:
            paths.append(DictPath(path))
        _regex = deep_get(kwargs, DictPath("regex"))
        if _regex is not None:
            compiled_regex = re.compile(_regex)
        for i, item in enumerate(deep_get_with_fallback(obj, paths, [])):
            if not item:
                continue
            if _regex is not None:
                if (re_tmp := compiled_regex.match(item)) is not None:
                    tmp2 = []
                    for group in re_tmp.groups():
                        if group is not None:
                            tmp2.append(group)
                    vlist.append(tmp2)
            else:
                if index_template:
                    vlist.append({"fields": [index_template.replace("<<<index>>>", f"{i}")],
                                  "ref": item})
                else:
                    vlist.append([item])
    elif "paths" in kwargs:
        paths = deep_get(kwargs, DictPath("paths"), [])
        if deep_get(kwargs, DictPath("named_lists")):
            for d in paths:
                path = deep_get(d, DictPath("path"))
                name = deep_get(d, DictPath("name"))
                tmp = deep_get(obj, DictPath(path), [])
                if not isinstance(tmp, list):
                    tmp = [tmp]
                for item in tmp:
                    vlist.append({"fields": [name, item]})
            return vlist

        # Lists that run out of elements will return ""
        # strings will be treated as constants and thus returned for every row
        maxlen = 0
        for column in paths:
            tmp = deep_get(obj, DictPath(column))
            if isinstance(tmp, list):
                maxlen = max(len(tmp), maxlen)
        for i in range(maxlen):
            item = []
            for column in paths:
                tmp = deep_get(obj, DictPath(column))
                if isinstance(tmp, str):
                    item.append(tmp)
                elif isinstance(tmp, list):
                    if len(tmp) > i:
                        item.append(tmp[i])
                    else:
                        item.append(" ")
            vlist.append(item)
    return vlist
