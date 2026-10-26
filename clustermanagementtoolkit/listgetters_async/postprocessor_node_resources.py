# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Postprocessor for node resources.
"""

from typing import Any

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-branches
def add_resource(key: str, units: dict[str, list[str]],
                 resources: float | list[str],
                 resource: float | str | None) -> int | float | list[str]:
    """
    Add a resource to the node resource list.

        Parameters:
            key (str): The name of the resource
            units (dict): The list of known resource types
            resources (int|float|[str]): The current resources
            resource (int|float|str): The new resource to add
        Returns:
            (int|float|[str]): The new sum/list of resources
    """
    if resource is None:
        return resources

    if key in deep_get(units, DictPath("millicores"), []) and isinstance(resources, (int, float)):
        # Either float or [str]
        try:
            resources += cmtlib.normalise_cpu_usage_to_millicores(str(resource))
        except ValueError:
            if resources == 0:
                resources = []
            if isinstance(resources, list):
                resources.append(str(resource))
    elif key in deep_get(units, DictPath("mem"), []) and isinstance(resources, (int, float)):
        # Either int or [str]
        try:
            resources += cmtlib.normalise_mem_to_bytes(str(resource))
        except ValueError:
            if resources == 0:
                resources = []
            if isinstance(resources, list):
                resources.append(str(resource))
    else:
        val = resource
        try:
            val = int(resource)
        except ValueError:
            try:
                val = float(resource)
            except ValueError:
                pass
        if isinstance(val, (int, float)) \
                and isinstance(val, (int, float)) and isinstance(resources, (int, float)):
            resources += val
        elif isinstance(resources, list):
            resources.append(str(resource))
    return resources


def postprocessor_node_resources(**kwargs: Any) -> tuple[list[dict], int | str]:
    """
    Postprocessor for node resources. Extracts the node resources
    from the list of all nodes and sums them up and groups them by type.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                vlist ([dict]): The list of node data
                status (int|str): The status of the data fetch
                units (dict): A dict of units for various resources
        Returns:
            (([dict], int|float)):
                ([dict]): A list of dicts for each resource
                (int|str): The status of the data fetch
    """
    vlist = deep_get(kwargs, DictPath("vlist"), [])
    status = deep_get(kwargs, DictPath("status"))
    units = deep_get(kwargs, DictPath("units"), {})
    resources: dict = {}
    vresources: list[dict] = []

    if status == 200:
        for node in vlist:
            capacities = deep_get(node, DictPath("status#capacity"), {})
            allocatables = deep_get(node, DictPath("status#allocatable"), {})
            for key, capacity in capacities.items():
                if key not in resources:
                    resources[key] = {"capacity": 0, "allocatable": 0}
                resources[key]["capacity"] = \
                    add_resource(key, units, resources[key]["capacity"], capacity)
                resources[key]["allocatable"] = \
                    add_resource(key, units, resources[key]["allocatable"],
                                 deep_get(allocatables, DictPath(key)))
        for resource, data in resources.items():
            vresources.append({
                "name": resource,
                "allocatable": deep_get(data, DictPath("allocatable"), 0),
                "capacity": deep_get(data, DictPath("capacity"), 0),
            })

    return vresources, status
