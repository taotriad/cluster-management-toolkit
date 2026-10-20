# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a dict and a focus filter, return the data with the filtered paths pruned.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_pop


def apply_focus_filter(obj: dict, **kwargs: Any) -> dict:
    """
    Given a dict and a focus filter, return the data with the filtered paths pruned.

        Parameters:
            obj (dict): The data to filter
            **kwargs (dict[str, Any]): Keyword arguments
                focus_mode (str): Disabled: No filtering
                                  <key>,...: Name of other filters
                focus_filters (dict[str, str|[str]]): A dict of a list of key or path + key
    """
    focus_mode: str = deep_get(kwargs, DictPath("focus_mode"), "Disabled")
    focus_filters: list[dict[str, list[str]]] = deep_get(kwargs, DictPath("focus_filters"), {})

    if not focus_mode or focus_mode not in focus_filters:
        return obj

    for focus_filter in deep_get(focus_filters, DictPath(focus_mode), []):
        if isinstance(focus_filter, list):
            path, key = focus_filter
            deep_pop(obj, DictPath(path), key, None)
        else:
            obj.pop(focus_filter, None)

    return obj
