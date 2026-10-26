# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the endpoints for an endpoint slice.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=unused-argument
def get_endpointslices_endpoints(obj: dict[str, Any],
                                 **kwargs: Any) -> list[tuple[str, StatusGroup]]:
    """
    Get the endpoints for an endpoint slice.

        Parameters:
            obj (dict): The endpoint slice object to return endpoints for
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([(str, StatusGroup)]): A list of (address, status) for each endpoint
    """
    endpoints = []
    for endpoint in deep_get(obj, DictPath("endpoints"), []):
        for address in deep_get(endpoint, DictPath("addresses"), []):
            ready = deep_get(endpoint, DictPath("conditions#ready"), False)
            if ready:
                status_group = StatusGroup.OK
            else:
                status_group = StatusGroup.NOT_OK
            endpoints.append((address, status_group))
    if not endpoints:
        endpoints.append(("<none>", StatusGroup.UNKNOWN))
    return endpoints


# pylint: disable-next=unused-argument
def datagetter_eps_endpoints(obj: dict[str, Any],
                             **kwargs: Any) -> tuple[list[tuple[str, StatusGroup]], dict]:
    """
    A datagetter that returns the endpoints for an endpoint slice.

        Parameters:
            obj (dict): The endpoint slice object to return endpoints for
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            The return value from get_endpointslices_endpoints and an empty dict
    """
    return get_endpointslices_endpoints(obj), {}
