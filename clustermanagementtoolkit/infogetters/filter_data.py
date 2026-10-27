# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Filter data before returning it from an infogetter.
"""

from typing import Literal, TypedDict

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


class FilterRuleType(TypedDict, total=True):
    """
    A allow/block filter rule.

        Parameters:
            key (str): The key to match
            values ([str]): The allowed/blocked valeus for that key
    """
    key: str
    values: list[str]


class FilterType(TypedDict, total=False):
    """
    A filter that allows or blocks the output from an infogetter.

        Parameters:
            allow ([FilterRuleType]): A list of allow rules
            block ([FilterRuleType]): A list of block rules
            enabled (bool): Enable/disable this rule (can be toggled with toggle_var)
            source (["caller", "object", ""]): Is the data source the caller or the object?
                                               [default: caller]
    """
    allow: list[FilterRuleType]
    block: list[FilterRuleType]
    enabled: bool
    source: Literal["caller", "object", ""]


def filter_data(filters: dict[str, FilterType], obj: dict,
                caller_obj: dict, deleted: bool) -> dict | None:
    """
    Given a set of filters, an object to extract data from,
    and a dict with ready-processed data, filter out data
    not allowed by the filter.

        Parameters:
            filter (dict[str, FilterType]): A set of filters
            obj (dict): The input data to the infogetter
            d (dict): The data processed by the infogetter
            deleted (bool): True if the object is flagged as deleted, False if not
        Returns:
            (dict): The filtered data
    """
    skip = False
    entry = None

    for f_filter in filters.values():
        if not deep_get(f_filter, DictPath("enabled"), True):
            continue

        # If len(allow) > 0, we only allow fields that match.
        allow = deep_get(f_filter, DictPath("allow"), [])
        # If len(block) > 0, we skip fields that match.
        block = deep_get(f_filter, DictPath("block"), [])
        source = deep_get(f_filter, DictPath("source"), "")
        if source == "object":
            src = obj
        else:
            src = caller_obj
        if allow:
            # If all field + value pairs match we allow.
            for rule in allow:
                key = deep_get(rule, DictPath("key"), "")
                values = deep_get(rule, DictPath("values"), "")

                if deep_get(src, DictPath(key), "").rstrip() not in values:
                    skip = True
                    break
        if block:
            # If all field + value pairs match we block.
            for rule in block:
                key = deep_get(rule, DictPath("key"), "")
                values = deep_get(rule, DictPath("values"), "")
                if deep_get(src, DictPath(key), "").rstrip() in values:
                    skip = True
                    break
        if skip:
            break

    if not skip:
        # Add the reference in the caller_obj.
        caller_obj["ref"] = obj
        caller_obj["__deleted"] = deleted
        caller_obj["__uid"] = deep_get(obj, DictPath("metadata#uid"))
        entry = dict(caller_obj)

    return entry
