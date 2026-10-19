# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the endpoints of a list of subsets.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get


def get_endpoint_endpoints(subsets: list[dict]) -> list[tuple[str, StatusGroup]]:
    """
    Get the endpoints for an endpoint.

        Parameters:
            subsets ([subset]): The subsets to return endpoints for
        Returns:
            ([(str, StatusGroup)]): A list of tuples with address and status for each endpoint
    """
    endpoints = []

    if subsets is None:
        subsets = []

    for subset in subsets:
        for address in deep_get(subset, DictPath("addresses"), []):
            endpoints.append((deep_get(address, DictPath("ip")), StatusGroup.OK))
        for address in deep_get(subset, DictPath("notReadyAddresses"), []):
            endpoints.append((deep_get(address, DictPath("ip")), StatusGroup.NOT_OK))

    if not endpoints:
        endpoints.append(("<none>", StatusGroup.UNKNOWN))

    return endpoints


def datagetter_endpoint_ips(obj: dict[str, Any],
                            **kwargs: Any) -> tuple[list[tuple[str, StatusGroup]], dict]:
    """
    A datagetter that returns the endpoints for an endpoint.

        Parameters:
            obj (dict): The endpoint object to return endpoints for
            **kwargs (dict[str, Any]): Keyword arguments
               (str): The path to the endpoint subsets
        Returns:
            (([(str, StatusGroup)], dict)):
                ([(str, StatusGroup)]): A list of tuples with address and status for each endpoint
                (dict): An empty dict
    """
    path = deep_get(kwargs, DictPath("path"))

    subsets = deep_get(obj, DictPath(path))
    endpoints = get_endpoint_endpoints(subsets)
    return endpoints, {}
