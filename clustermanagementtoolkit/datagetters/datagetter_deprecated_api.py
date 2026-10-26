# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return information about deprecated APIs.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.datagetters.datagetter_metrics import datagetter_metrics

from clustermanagementtoolkit.kubernetes_helper import guess_kind


def datagetter_deprecated_api(obj: dict[str, Any],
                              **kwargs: Any) -> tuple[tuple[str, str, str], dict]:
    """
    A datagetter that returns deprecated API information for the specified path.

        Parameters:
            obj (dict): The object with metrics
            kwargs (dict):
        **kwargs (dict[str, Any]): Keyword arguments
            path (str): The path to the metrics to get
            default ([str]): The list to return if obj or path is None
        Returns:
            (str, str, [str], dict):
                (str): Kind for the deprecated API
                (str): API-family for the deprecated API
                ([str]): Metrics for the deprecated API
                (dict): Additional vars
    """
    path = deep_get(kwargs, DictPath("path"))
    default = deep_get(kwargs, DictPath("default"), [])

    result, extra_vars = datagetter_metrics(obj, path=path, default=default)
    kind, api_family = guess_kind((result[0], result[1]))
    return (kind, api_family, result[2]), extra_vars
