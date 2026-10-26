# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of OpenShift Feature Gates.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def listgetter_feature_gates(obj: dict, **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Listgetter for FeatureGate.config.openshift.io.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the list of feature gates
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list of data
                (int): The status for the request
    """
    vlist = []
    path = deep_get(kwargs, DictPath("path"))

    for payload_version_data in deep_get(obj, DictPath(path), []):
        version = deep_get(payload_version_data, DictPath("version"), "<unknown>")
        for enabled_feature_gate in deep_get(payload_version_data, DictPath("enabled"), []):
            name = deep_get(enabled_feature_gate, DictPath("name"), "<unknown>")
            item = {
                "enabled": True,
                "version": version,
                "name": name,
            }
            vlist.append(item)
        for disabled_feature_gate in deep_get(payload_version_data, DictPath("disabled"), []):
            name = deep_get(disabled_feature_gate, DictPath("name"), "<unknown>")
            item = {
                "enabled": False,
                "version": version,
                "name": name,
            }
            vlist.append(item)
    return vlist, 200
