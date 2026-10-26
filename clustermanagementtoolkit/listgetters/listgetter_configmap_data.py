# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of data in a ConfigMap.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.formatters import format_binary
from clustermanagementtoolkit.formatters import identify_cmdata


# pylint: disable-next=unused-argument
def listgetter_configmap_data(obj: dict, **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Get a list of the data in a configmap.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list of data
                (int): The status for the request
    """
    vlist: list[dict[str, Any]] = []

    cm_name = deep_get(obj, DictPath("metadata#name"))
    cm_namespace = deep_get(obj, DictPath("metadata#namespace"), "")

    for key, value in deep_get(obj, DictPath("binaryData"), {}).items():
        data_type, formatter = identify_cmdata(key, cm_name, cm_namespace, value)
        # This is from a data section, but it was identified as Text... Hmmm.
        # Assume it's Binary just in case.
        if data_type == "Text":
            data_type = "Binary"

        vlist.append({
            "cm_name": cm_name,
            "cm_namespace": cm_namespace,
            "configmap": key,
            "type": data_type,
            "formatter": format_binary,
            "data": value,
        })

    for key, value in deep_get(obj, DictPath("data"), {}).items():
        data_type, formatter = identify_cmdata(key, cm_name, cm_namespace, value)
        vlist.append({
            "cm_name": cm_name,
            "cm_namespace": cm_namespace,
            "configmap": key,
            "type": data_type,
            "formatter": formatter,
            "data": value,
        })

    return vlist, 200
