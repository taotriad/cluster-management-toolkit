# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get


def get_eps_subsets_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for EndpointSlice subsets.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                _obj (dict): The dict to extract data from
        Returns:
            info ([dict]): A list with info
    """
    if (obj := deep_get(kwargs, DictPath("_obj"))) is None:
        return []

    addresstype = deep_get(obj, DictPath("addressType"))
    subsets = []
    ports = []

    for port in deep_get(obj, DictPath("ports"), []):
        port_name = deep_get(port, DictPath("name"), "")
        ports.append((port_name, deep_get(port, DictPath("port")),
                      deep_get(port, DictPath("protocol"))))

    for endpoint in deep_get(obj, DictPath("endpoints"), []):
        ready_addresses = []
        not_ready_addresses = []

        for address in deep_get(endpoint, DictPath("addresses"), []):
            if deep_get(endpoint, DictPath("conditions#ready")):
                ready_addresses.append(address)
            else:
                not_ready_addresses.append(address)
        target_ref = (deep_get(endpoint, DictPath("targetRef#kind"), ""),
                      deep_get(endpoint, DictPath("targetRef#apiVersion"), ""),
                      deep_get(endpoint, DictPath("targetRef#namespace"), ""),
                      deep_get(endpoint, DictPath("targetRef#name"), ""))
        topology = []
        # If nodeName is available this is the new API
        # where topology is replaced by nodeName and zone
        if "nodeName" in endpoint:
            topology.append(("nodeName", deep_get(endpoint, DictPath("nodeName"), "<unset>")))
            if "zone" in endpoint:
                topology.append(("zone", deep_get(endpoint, DictPath("zone"), "<unset>")))
        else:
            for key, value in deep_get(endpoint, DictPath("topology"), {}).items():
                topology.append((key, value))

        if ready_addresses:
            subsets.append({
                "addresstype": addresstype,
                "addresses": ready_addresses,
                "ports_eps": ports,
                "status": "Ready",
                "status_group": StatusGroup.OK,
                "target_ref": target_ref,
                "topology": topology,
                "ready": deep_get(endpoint, DictPath("conditions#ready")),
                "serving": deep_get(endpoint, DictPath("conditions#serving")),
                "terminating": deep_get(endpoint, DictPath("conditions#terminating")),
            })
        if not_ready_addresses:
            subsets.append({
                "addresstype": addresstype,
                "addresses": not_ready_addresses,
                "ports_eps": ports,
                "status": "Not Ready",
                "status_group": StatusGroup.NOT_OK,
                "target_ref": target_ref,
                "topology": topology,
                "ready": deep_get(endpoint, DictPath("conditions#ready")),
                "serving": deep_get(endpoint, DictPath("conditions#serving")),
                "terminating": deep_get(endpoint, DictPath("conditions#terminating")),
            })
    return subsets
