# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-locals,too-many-branches
def get_dict_list(obj: dict, **kwargs: Any) -> list[Any]:
    """
    Given a path to a dict (or a list of dicts), generate a list with all items
    as a list of dicts with the key and the value in the fields as "key" and "value",
    respectively, where value can itself be any type, not just simple types;
    fields is then used to further specify the path to the individual fields
    to form the final list from.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the dict
        Returns:
            list[dict]: A list of data
    """
    vlist: list[Any] = []
    tmp_vlist = []

    path: str | DictPath = deep_get(kwargs, DictPath("path"))
    fields = deep_get(kwargs, DictPath("fields"))

    data: dict | list[dict] = deep_get(obj, DictPath(path), [])

    if isinstance(data, dict):
        data = [data]

    for item in data:
        for key, value in item.items():
            tmp_vlist.append({"key": key, "value": value})

    # pylint: disable-next=too-many-nested-blocks
    for item in tmp_vlist:
        newobj: list[tuple] = []
        for field in fields:
            if isinstance(field, dict):
                field_ = deep_get(field, DictPath("field"), "")
                field_regex = deep_get(field, DictPath("regex"), "")
                if (tmp := deep_get(item, DictPath(field_))) is not None:
                    tmp = str(tmp)
                    if field_regex:
                        if (re_tmp := re.match(field_regex, tmp)) is not None:
                            tmp = re_tmp.group(1)
                        else:
                            tmp = " "
                else:
                    tmp = " "
            else:
                if (tmp := deep_get(item, DictPath(field))) is not None:
                    tmp = str(tmp)
                else:
                    tmp = " "
            newobj.append(tmp)
        if newobj:
            vlist.append(tuple(newobj))
    return vlist
