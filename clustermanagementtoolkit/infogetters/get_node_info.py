# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmtlib import get_since
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.infogetters.get_node_addresses import get_node_addresses

from clustermanagementtoolkit.kubernetes_helper import get_node_roles
from clustermanagementtoolkit.kubernetes_helper import get_node_status


# pylint: disable-next=too-many-locals
def get_node_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Nodes.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                vlist ([dict[str, Any]]): The list of Node objects
        Returns:
            info (list[dict]): A list with info
    """
    info: list[dict] = []

    if (vlist := deep_get(kwargs, DictPath("vlist"))) is None or not vlist:
        return []

    for obj in vlist:
        name = deep_get(obj, DictPath("metadata#name"))
        # For now we do not do anything with external IPs; we should
        hostname, internal_ips, _external_ips = \
            get_node_addresses(deep_get(obj, DictPath("status#addresses")))
        ref = obj
        kubernetes_roles = get_node_roles(obj)
        timestamp = \
            timestamp_to_datetime(deep_get(obj, DictPath("metadata#creationTimestamp")))
        age = get_since(timestamp)
        cpu = (deep_get(obj, DictPath("status#allocatable"))["cpu"],
               deep_get(obj, DictPath("status#capacity"))["cpu"])
        # Strip Ki suffix
        mem = (deep_get(obj, DictPath("status#allocatable"))["memory"][:-2],
               deep_get(obj, DictPath("status#capacity"))["memory"][:-2])
        status, status_group, taints, _full_taints = get_node_status(obj)
        kubelet_version = deep_get(obj, DictPath("status#nodeInfo#kubeletVersion"))
        container_runtime = deep_get(obj, DictPath("status#nodeInfo#containerRuntimeVersion"))
        operating_system = deep_get(obj, DictPath("status#nodeInfo#osImage"))
        kernel = deep_get(obj, DictPath("status#nodeInfo#kernelVersion"))

        info.append({
            "name": name,
            "hostname": hostname,
            "ref": ref,
            "status": status,
            "status_group": status_group,
            "kubernetes_roles": kubernetes_roles,
            "age": age,
            "kubelet_version": kubelet_version,
            "internal_ips": internal_ips,
            "os": operating_system,
            "kernel": kernel,
            "container_runtime": container_runtime,
            "cpu": cpu,
            "mem": mem,
            "taints": taints,
        })

    return info
