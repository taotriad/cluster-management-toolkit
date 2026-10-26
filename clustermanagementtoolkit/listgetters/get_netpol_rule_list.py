# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of network policy rules.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=unused-argument,too-many-locals,too-many-branches
def get_netpol_rule_list(obj: dict, **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Get a list of network policy rules.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The network policy rules
                (int): The status for the request
    """
    vlist: list[dict[str, Any]] = []
    status: int = 200

    for item in deep_get(obj, DictPath("spec#ingress"), []):
        action: str = deep_get(item, DictPath("action"), "")
        name: str = deep_get(item, DictPath("name"), "")
        policy_type = "Ingress"

        ports = []
        for port in deep_get(item, DictPath("ports"), []):
            ports.append({
                "name": deep_get(port, DictPath("namedPort"), ""),
                "port": deep_get(port, DictPath("portNumber#port"), ""),
                "protocol": deep_get(port, DictPath("portNumber#protocol"), ""),
            })

        pod_selectors = []
        pod_namespace_selectors = []
        namespace_selectors = []

        from_rules = deep_get(item, DictPath("from"), [])

        for source in from_rules:
            if (tmp := deep_get(source, DictPath("namespaces"), {})):
                namespace_selectors.append(tmp)
            if (tmp := deep_get(source, DictPath("pods#namespaceSelector"), {})):
                pod_namespace_selectors.append(tmp)
            if (tmp := deep_get(source, DictPath("pods#podSelector"), {})):
                pod_selectors.append(tmp)

            vlist.append({
                "name": name,
                "action": action,
                "policy_type": policy_type,
                "ports": ports,
                "pod_selectors": pod_selectors,
                "pod_namespace_selectors": pod_namespace_selectors,
                "namespace_selectors": namespace_selectors,
                # Only used by egress rules
                "nodes": [],
                "networks": [],
                "domains": [],
            })

    for item in deep_get(obj, DictPath("spec#egress"), []):
        action = deep_get(item, DictPath("action"), "")
        name = deep_get(item, DictPath("name"), "")
        policy_type = "Egress"

        ports = []
        for port in deep_get(item, DictPath("ports"), []):
            ports.append({
                "name": deep_get(port, DictPath("namedPort"), ""),
                "port": deep_get(port, DictPath("portNumber#port"), ""),
                "protocol": deep_get(port, DictPath("portNumber#protocol"), ""),
            })

        domains = []
        namespace_selectors = []
        networks = []
        node_selectors = []
        pod_namespace_selectors = []
        pod_selectors = []

        to_rules = deep_get(item, DictPath("to"), [])

        for source in to_rules:
            domains += deep_get(source, DictPath("domainNames"), [])
            if (tmp := deep_get(source, DictPath("namespaces"), {})):
                namespace_selectors.append(tmp)
            networks += deep_get(source, DictPath("networks"), [])
            if (tmp := deep_get(source, DictPath("nodes"), {})):
                node_selectors.append(tmp)
            if (tmp := deep_get(source, DictPath("pods#namespaceSelector"), {})):
                pod_namespace_selectors.append(tmp)
            if (tmp := deep_get(source, DictPath("pods#podSelector"), {})):
                pod_selectors.append(tmp)

        vlist.append({
            "name": name,
            "action": action,
            "policy_type": policy_type,
            "ports": ports,
            "pod_selectors": pod_selectors,
            "pod_namespace_selectors": pod_namespace_selectors,
            "namespace_selectors": namespace_selectors,
            "node_selectors": node_selectors,
            "networks": networks,
            "domains": domains,
        })

    return vlist, status
