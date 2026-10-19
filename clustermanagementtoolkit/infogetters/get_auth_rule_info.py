# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-locals
def get_auth_rule_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Istio Authorization Policy Rules.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                _obj (dict): The dict to extract data from
        Returns:
            ([dict]): A list with info
    """
    obj = deep_get(kwargs, DictPath("_obj"))
    info: list[dict] = []

    if obj is None:
        return []

    for item in deep_get(obj, DictPath("spec#rules"), []):
        sources = []
        operations = []
        conditions = []

        for source in deep_get(item, DictPath("from"), []):
            principals = ",".join(deep_get(source, DictPath("source#principals"), []))
            not_principals = ",".join(deep_get(source, DictPath("source#notPrincipals"), []))
            request_principals = \
                ",".join(deep_get(source, DictPath("source#requestPrincipals"), []))
            not_request_principals = \
                ",".join(deep_get(source, DictPath("source#notRequestPrincipals"), []))
            namespaces = ",".join(deep_get(source, DictPath("source#namespaces"), []))
            not_namespaces = ",".join(deep_get(source, DictPath("source#notNamespaces"), []))
            ip_blocks = ",".join(deep_get(source, DictPath("source#ipBlocks"), []))
            not_ip_blocks = ",".join(deep_get(source, DictPath("source#notIpBlocks"), []))
            sources.append((principals, not_principals,
                            request_principals, not_request_principals,
                            namespaces, not_namespaces,
                            ip_blocks, not_ip_blocks))

        for operation in deep_get(item, DictPath("to"), []):
            hosts = ",".join(deep_get(operation, DictPath("operation#hosts"), []))
            not_hosts = ",".join(deep_get(operation, DictPath("operation#notHosts"), []))
            ports = ",".join(deep_get(operation, DictPath("operation#ports"), []))
            not_ports = ",".join(deep_get(operation, DictPath("operation#notPorts"), []))
            methods = ",".join(deep_get(operation, DictPath("operation#methods"), []))
            not_methods = ",".join(deep_get(operation, DictPath("operation#notMethods"), []))
            paths = ",".join(deep_get(operation, DictPath("operation#paths"), []))
            not_paths = ",".join(deep_get(operation, DictPath("operation#notPaths"), []))
            operations.append((hosts, not_hosts,
                               ports, not_ports,
                               methods, not_methods,
                               paths, not_paths))

        for condition in deep_get(item, DictPath("when"), []):
            key = deep_get(condition, DictPath("key"))
            values = ",".join(deep_get(condition, DictPath("values"), []))
            not_values = ",".join(deep_get(condition, DictPath("notValues"), []))
            conditions.append((key, values, key, not_values))

        if sources or operations or conditions:
            info.append({
                "sources": sources,
                "operations": operations,
                "conditions": conditions,
            })
    return info
