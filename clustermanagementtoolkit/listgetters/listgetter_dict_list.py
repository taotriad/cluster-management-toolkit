# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of dict created from a dict in a way that allows for addressing
fields in a dict we don't know the key-names in.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def listgetter_dict_list(obj: dict[str, Any], **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Given a dict, return a list of dicts.
    The format of the newly generated dict is:
    {"key": key_from_dict, "value": value_from_dict}
    This is to ensure that we can get the key without knowing the name of the key.

    If multiple paths are provided they will be merged as {"key_name": key_value, "value": value};
    this form can be used if you have multiple dicts that you want to use as a list.

        Parameters:
            obj (dict): The object to convert to a list
            path (str): The path to get the data from
            paths (str): The paths to get the data from
            join_paths (bool): Merge multiple data sources into one
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list representation of the dict
                (int): The status for the request
    """
    path = deep_get(kwargs, DictPath("path"))
    paths = deep_get(kwargs, DictPath("paths"))
    join_paths: bool = deep_get(kwargs, DictPath("join_paths"), False)
    vlist = []
    if paths and join_paths:
        new_obj: dict[str, Any] = {}
        # First we need to join the paths
        for item in paths:
            path = deep_get(item, DictPath("path"), "")
            for key, value in deep_get(obj, DictPath(path), {}).items():
                if key not in new_obj:
                    new_obj[key] = {}
                new_obj[key].update(value)
        # Now we can create the list
        for key, value in new_obj.items():
            vlist.append({"key": key, "value": value})
    elif path:
        for key, value in deep_get(obj, DictPath(path), {}).items():
            vlist.append({"key": key, "value": value})
    elif paths:
        for item in paths:
            path = deep_get(item, DictPath("path"), "")
            key_name = deep_get(item, DictPath("key_name"), "key")
            key_value = deep_get(item, DictPath("key_value"))
            entry: dict[str, Any] = {
                key_name: key_value,
                "value": deep_get(obj, path),
            }
            vlist.append(entry)
    return vlist, 200
