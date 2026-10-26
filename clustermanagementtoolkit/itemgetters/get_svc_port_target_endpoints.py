# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns the endpoints for a Service port.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.itemgetters.get_endpoint_ips import get_endpoint_ips


# pylint: disable-next=too-many-locals
def get_svc_port_target_endpoints(obj: dict, **kwargs: Any) -> list[tuple[str, str, str, str]]:
    """
    Get the Service port target endpoints.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            ([(str, str, str, str)]): A list of Service port target endpoints
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    svcname = deep_get(obj, DictPath("metadata#name"))
    svcnamespace = deep_get(obj, DictPath("metadata#namespace"))
    port_target_endpoints = []
    stype = deep_get(obj, DictPath("spec#type"))
    cluster_ip = deep_get(obj, DictPath("spec#clusterIP"))
    endpoints = []

    ref = kh.get_ref_by_kind_name_namespace(("Endpoints", ""),
                                            svcname, svcnamespace, resource_cache=kh_cache)
    endpoints = get_endpoint_ips(deep_get(ref, DictPath("subsets")))

    for port in deep_get(obj, DictPath("spec#ports"), []):
        name = deep_get(port, DictPath("name"), "")
        svcport = deep_get(port, DictPath("port"), "")
        protocol = deep_get(port, DictPath("protocol"), "")
        if stype in ("NodePort", "LoadBalancer"):
            node_port = deep_get(port, DictPath("nodePort"), "Auto Allocate")
        else:
            node_port = "N/A"
        if cluster_ip is not None:
            target_port = deep_get(port, DictPath("targetPort"), "")
        else:
            target_port = "<none>"
        endpointstr = f":{target_port}, ".join(endpoints)
        endpointstr += f":{target_port}"
        port_target_endpoints.append((f"{name}:{svcport}/{protocol}",
                                      f"{node_port}", f"{target_port}/{protocol}", endpointstr))

    return port_target_endpoints
