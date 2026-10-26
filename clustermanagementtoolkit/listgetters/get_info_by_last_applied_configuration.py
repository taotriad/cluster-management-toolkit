# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given an API-tuple, return the last applied configuration.
"""

import json
from typing import Any, cast

from clustermanagementtoolkit.cmtio_yaml import json_loads

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-locals
def get_info_by_last_applied_configuration(obj: dict, **kwargs: Any) -> tuple[list[dict], int]:
    """
    Given a kind tuple, get a list of all its resources, and check for a last applied
    configuration, optionally matching by API-version.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                kind ((str, str)): The kind tuple to get resources for
                group_path (str): The path to get the group from
                version_path (str): The path to get the version from
                match_api_version (bool): Should the information be filtered by API-version?
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list of pod resources.
                (int): The status for the request
        Raises:
            ProgrammingError: Function called without kubernetes_helper
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    if (kind := deep_get(kwargs, DictPath("kind"), ("", ""))) == ("", ""):
        return [], 404

    configuration: dict[str, str] = {
        "kind": kind[0]
    }

    if deep_get(kwargs, DictPath("match_api_version"), False):
        version_path = deep_get(kwargs, DictPath("version_path"))
        group_path = deep_get(kwargs, DictPath("group_path"))
        api_version = f"{deep_get(obj, DictPath(group_path))}/" \
                      f"{deep_get(obj, DictPath(version_path))}"
        configuration["apiVersion"] = api_version

    resource_info: list[dict] = []

    items, status = kh.get_list_by_kind_namespace(kind, "", resource_cache=kh_cache)
    if status != 200:
        return resource_info, status

    for item in items:
        last_applied_configuration = \
            deep_get(item, DictPath("metadata#annotations#kubectl.kubernetes.io/"
                                    "last-applied-configuration"), {})
        if last_applied_configuration is None or not last_applied_configuration:
            continue
        try:
            # last-applied-configuration is always a dict, not a list.
            data: dict[str, Any] = cast(dict[str, Any], json_loads(last_applied_configuration))
        except (ValueError, json.decoder.JSONDecodeError):
            # The data is malformed; skip the entry
            continue

        match = True
        for key, conf in configuration.items():
            if key not in data or conf != data[key]:
                match = False
                break
        if match:
            name = deep_get(item, DictPath("metadata#name"))
            namespace = deep_get(item, DictPath("metadata#namespace"), "")
            d = {
                "kind": kind,
                "metadata": {
                    "namespace": namespace,
                    "name": name,
                }
            }
            resource_info.append(d)

    return resource_info, status
