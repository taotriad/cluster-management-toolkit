# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns a list of conditions.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.cmtlib import timestamp_to_datetime


def get_conditions(obj: dict, **kwargs: Any) -> list[dict]:
    """
    Get a list of conditions.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the conditions list
        Returns:
            ([dict]): A list of conditions
    """
    condition_list = []

    path: str | DictPath = deep_get(kwargs, DictPath("path"), DictPath("status#conditions"))

    for condition in deep_get(obj, DictPath(path), []):
        ctype = deep_get(condition, DictPath("type"), "")
        status = deep_get_with_fallback(condition, [DictPath("status"), DictPath("phase")], "")
        reason = deep_get(condition, DictPath("reason"), "<unset>")
        last_transition = \
            deep_get_with_fallback(condition, [DictPath("lastTransitionTime"),
                                               DictPath("lastUpdateTime")])
        if last_transition is None:
            last_transition = "<unset>"
        else:
            timestamp = timestamp_to_datetime(last_transition)
            last_transition = f"{timestamp.astimezone():%Y-%m-%d %H:%M:%S}"
        message = deep_get(condition, DictPath("message"), "")
        condition_list.append({
            "fields": [ctype, status, reason, last_transition, message],
        })
    return condition_list
