# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Filter list entries.
"""

import sys
from typing import Any

from clustermanagementtoolkit.cmtlib import substitute_string

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


# Returns True if the item should be skipped
# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def filter_list_entry(obj: dict[str, Any], caller_obj: dict[str, Any], filters: dict) -> bool:
    """
    Filter an object based on a set of rules and return whether the object should be skipped
    Usage is typically to pass in an object from a listgetter (hence the name)
    and filter it against data in the referenced object.

        Parameters:
            obj (dict): The primary dict
            caller_obj (dict): The secondary dict
            filters (dict): The filters to apply
        Returns:
            (bool): True to deny the entry, False to allow the entry
    """
    skip: bool = False

    # pylint: disable-next=too-many-nested-blocks
    for f_filter in filters.values():
        if not deep_get(f_filter, DictPath("enabled"), True):
            continue

        # If len(allow) > 0, we only allow fields that match
        allow = deep_get(f_filter, DictPath("allow"), [])
        # If len(block) > 0, we skip fields that match
        block = deep_get(f_filter, DictPath("block"), [])
        if allow:
            # If all field + value pairs match we allow
            for rule in allow:
                rtype = deep_get(rule, DictPath("type"), "")
                if rtype == "":
                    key = deep_get(rule, DictPath("key"), "")
                    values = deep_get(rule, DictPath("values"), [])
                    substitutions = {}
                    for subst, subst_with in deep_get(rule, DictPath("substitutions"), {}).items():
                        if isinstance(subst_with, list):
                            subst_with = deep_get_with_fallback(caller_obj, subst_with)
                        substitutions[subst] = subst_with
                    key = substitute_string(key, substitutions)
                    if deep_get(rule, DictPath("values#source"), "object") == "caller":
                        src = caller_obj
                    else:
                        src = obj
                    if deep_get(rule, DictPath("exists"), False) and deep_get(src, DictPath(key)):
                        continue
                    if isinstance(values, dict):
                        values_path = deep_get(rule, DictPath("values#path"), "")
                        values = deep_get(src, DictPath(values_path), [])
                        if isinstance(values, str):
                            values = [values]

                    _listref = deep_get(rule, DictPath("list"))
                    if _listref is not None:
                        _list = deep_get(obj, DictPath(_listref), [])
                        for _item in _list:
                            if deep_get(_item, DictPath(key), "").rstrip() in values:
                                break
                        else:
                            skip = True
                            break
                    elif deep_get(obj, DictPath(key), "").rstrip() not in values:
                        skip = True
                        break
                elif rtype == "dictlist":
                    path = deep_get(rule, DictPath("path"), "")
                    target_dict = deep_get(obj, DictPath(path), {})
                    matched = False
                    for _dict in target_dict:
                        for key, value in deep_get(rule, DictPath("fields"), {}).items():
                            if isinstance(value, dict):
                                if deep_get(value, DictPath("source"), "object") == "caller":
                                    src = caller_obj
                                else:
                                    src = target_dict
                                value_path = deep_get(value, DictPath("path"), "")
                                if value_path:
                                    value = deep_get(src, DictPath(value_path))
                            if key == "api_family":
                                target_value = deep_get(_dict, DictPath("apiVersion"))
                                if "/" in target_value:
                                    target_value = target_value.split("/", 1)[0]
                                else:
                                    target_value = ""
                            else:
                                target_value = deep_get(_dict, DictPath(key))
                            if type(value) == type(target_value) \
                                    and value == target_value:  # noqa: E721
                                matched = True
                            else:
                                # This particular dict did not fully match
                                matched = False
                                break
                        if matched:
                            break
                    if not matched:
                        skip = True
                        break
                else:
                    sys.exit(f"filter: unknown rule-type: {rtype}")

        if block:
            # If all field + value pairs match we block
            for rule in block:
                key = deep_get(rule, DictPath("key"), "")
                values = deep_get(rule, DictPath("values"), [])
                if isinstance(values, dict):
                    if deep_get(rule, DictPath("values#source"), "object") == "caller":
                        src = caller_obj
                    else:
                        src = obj
                    values_path = deep_get(rule, DictPath("values#path"), "")
                    values = deep_get(src, DictPath(values_path), [])
                    if isinstance(values, str):
                        values = [values]
                if deep_get(obj, DictPath(key), "").rstrip() in values:
                    skip = True
                    break
        if skip:
            break
    return skip
