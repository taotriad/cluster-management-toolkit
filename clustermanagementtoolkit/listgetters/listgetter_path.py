# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return data from a path or list of paths.
"""

import copy
from itertools import zip_longest
from typing import Any, cast

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_set


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def listgetter_path(obj: dict, **kwargs: Any) -> tuple[dict | list[dict], int]:
    """
    Listgetter for paths.

        Parameters:
            obj (Dict): The object to extract a list of data from
            **kwargs (dict[str, Any]): Keyword arguments
                enumeration (str): How to enumerate items ("standard", "reverse", "")
                flatten_dicts (bool): Should dicts be flattened?
                join_key (str): Key to use when joining multiple dict lists;
                                note that currently at least the actual value is unused;
                                but if this is set it joins.
                multipath (str): A path to a dict containing multiple lists
                paths ([str]): A list of paths to get data from
                rename_bare (str): Name to use for the key when renaming bare lists
        Returns:
            (vlist, retval):
                vlist (list[dict]): The list of data
                retval (int): The return value
    """
    vlists = []
    vlist = []
    tmp: Any = None

    rename_bare: str = deep_get(kwargs, DictPath("rename_bare"), None)
    flatten_dicts: bool = deep_get(kwargs, DictPath("flatten_dicts"), False)
    paths: list[str] = deep_get(kwargs, DictPath("paths"))
    multipath: str = deep_get(kwargs, DictPath("multipath"))
    join_key: str = deep_get(kwargs, DictPath("join_key"))
    # "standard", "reverse", ""
    enumeration: str = deep_get(kwargs, DictPath("enumeration"), "")
    hierarchical: bool = deep_get(kwargs, DictPath("hierarchical"), False)

    # A multipath is a path to a dict that in turn contains lists, where you'd want the name
    # of the path containing the lists as a newly created key
    if multipath:
        for d in deep_get(kwargs, DictPath("subpaths"), []):
            path = deep_get(d, DictPath("path"))
            key_name = deep_get(d, DictPath("key_name"), "_key")
            key_value = deep_get(d, DictPath("key_value"), path)
            value_name = deep_get(d, DictPath("value_name"), "_value")

            for item in deep_get(obj, DictPath(f"{multipath}#{path}"), []):
                if isinstance(item, dict):
                    tmp = copy.deepcopy(item)
                    tmp[value_name] = key_value
                else:
                    tmp = {
                        key_name: key_value,
                        value_name: copy.deepcopy(item),
                    }
                vlist.append(tmp)
        return vlist, 200

    # pylint: disable-next=too-many-nested-blocks
    if paths is not None:
        for path in paths:
            ppath = deep_get(path, DictPath("path"))
            ptype = deep_get(path, DictPath("type"), "value")
            key_name = deep_get(path, DictPath("key_name"))
            key_value = deep_get(path, DictPath("key_value"))

            if ptype == "list":
                tmp = []
                for item in deep_get(obj, DictPath(ppath), []):
                    tmpitem = copy.deepcopy(item)
                    if key_name is not None and key_value is not None:
                        tmpitem[key_name] = key_value
                    tmp.append(tmpitem)
                vlists.append(tmp)
            else:
                for key in deep_get(obj, DictPath(ppath), []):
                    for item in deep_get(obj, DictPath(f"{ppath}#{key}"), []):
                        tmpitem = copy.deepcopy(item)
                        if key_name is not None and key_value is not None:
                            tmpitem[key_name] = key_value
                        vlist.append(tmpitem)
        if join_key is None:
            for tmp in vlists:
                vlist += tmp
        else:
            # XXX: What was intended here? join_key isn't used
            for tmp in vlists:
                vlist = [{**u, **v} for u, v in cast(dict, zip_longest(vlist, tmp, fillvalue={}))]
        return vlist, 200

    path = deep_get(kwargs, DictPath("path"))
    subpath = deep_get(kwargs, DictPath("subpath"))
    path_fields = deep_get(kwargs, DictPath("path_fields"))

    # As a special case passing the empty string as path will return the object instead of a list
    if not path:
        return obj, 200

    # If a subpath and path_fields are set path_fields from path will be merged into subpath
    # and the subpath lists are flattened into the path list.
    # pylint: disable-next=too-many-nested-blocks
    if subpath is not None and path_fields is not None:
        for item in deep_get(obj, DictPath(path), []):
            for subobj in deep_get(item, DictPath(subpath), []):
                for path_field in path_fields:
                    subobj[path_field] = deep_get(item, DictPath(path_field))
                vlist.append(subobj)
    else:
        tmp2: list[dict[str, Any]] = deep_get(obj, DictPath(path), [])
        vlist = []
        if rename_bare is not None and tmp2 is not None:
            for uuid, dictitem in enumerate(tmp2):
                if not isinstance(dictitem, dict):
                    d = {rename_bare: dictitem, "uuid": uuid}
                    if flatten_dicts and isinstance(deep_get(tmp2, DictPath(dictitem)), dict):
                        for key, value in deep_get(tmp2, DictPath(dictitem), {}).items():
                            d[key] = value
                    vlist.append(d)
                else:
                    vlist.append(dictitem)
        elif flatten_dicts and tmp2 is not None:
            for item in tmp2:
                d = {}
                for key, value in item.items():
                    d["key"] = key
                    d["value"] = value
                    vlist.append(d)
        elif enumeration:
            for i, item in enumerate(tmp2):
                if isinstance(item, dict):
                    if enumeration == "standard":
                        deep_set(item, DictPath("_extra_data#enumeration"), i,
                                 create_path=True)
                    elif enumeration == "reverse":
                        deep_set(item, DictPath("_extra_data#enumeration"), len(tmp2) - i,
                                 create_path=True)
                    hierarchy_prefix: str = ""
                    if hierarchical and i > 0:
                        hierarchy_prefix = "".rjust(4 * (i - 1)) + "└── "
                    deep_set(item, DictPath("_extra_data#prefix"),
                             hierarchy_prefix, create_path=True)
                    vlist.append(item)
        else:
            vlist = tmp2

    return vlist, 200
