# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return metrics for a specified path.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def datagetter_metrics(obj: dict[str, Any], **kwargs: Any) -> tuple[list[str], dict]:
    """
    A datagetter that returns metrics for the specified path.

        Parameters:
            obj (dict): The object with metrics
            **kwargs (dict[str, Any]): Keyword arguments
                path (DictPath): The path to the metrics to get
                default ([str]): The list to return if obj or path is None
        Returns:
            result ([str]), {} (dict): A list with metrics and an empty dict
    """
    path = deep_get(kwargs, DictPath("path"))
    default: list[str] = deep_get(kwargs, DictPath("default"), [])

    if obj is None or not obj or path is None:
        return default, {}

    result = []

    for field in path:
        result.append(deep_get(obj, DictPath(f"fields#{field}"), ""))

    return result, {}
