# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_resource_list(obj: dict, **kwargs: Any) -> list[tuple[str, str, str]]:
    """
    Get a list of resources.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                capacity_path (str): The path to get capacity from
                allocatable_path (str): The path to get allocatable from
        Returns:
            ([(str, str)]): A list of resources
                (str): Resource
                (str): Allocatable
                (str): Capacity
    """
    vlist: list[tuple[str, str, str]] = []
    capacity_path: str = deep_get(kwargs, DictPath("capacity_path"),
                                  "status#capacity")
    allocatable_path: str = deep_get(kwargs, DictPath("allocatable_path"),
                                     "status#allocatable")

    for res in deep_get(obj, DictPath(capacity_path), {}):
        capacity = deep_get(obj, DictPath(f"{capacity_path}#{res}"), "")
        allocatable = deep_get(obj, DictPath(f"{allocatable_path}#{res}"), "")
        vlist.append((res, allocatable, capacity))
    return vlist
