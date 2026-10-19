# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the list of control planes.
"""

import errno
import sys
from typing import Any, cast

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper import KubernetesHelper
from clustermanagementtoolkit.kubernetes_helper import get_node_roles


def get_control_planes(**kwargs: Any) -> list[tuple[str, list[str]]]:
    """
    Get the list of control planes.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
        Returns:
            [(str, [str])]: The list of control planes
                (str): The name of the control plane
                ([str]): A list of IP-addresses for the control plane
    """
    kh: KubernetesHelper = deep_get(kwargs, DictPath("kubernetes_helper"))

    controlplanes = []

    vlist, status = kh.get_list_by_kind_namespace(("Node", ""), "")
    if status != 200:
        ansithemeprint([ANSIThemeStr("Error", "error"),
                        ANSIThemeStr(": API-server returned ", "default"),
                        ANSIThemeStr(f"{status}", "errorvalue"),
                        ANSIThemeStr("; aborting.", "default")], stderr=True)
        sys.exit(errno.EINVAL)
    if vlist is None:
        ansithemeprint([ANSIThemeStr("Error", "error"),
                        ANSIThemeStr(": API-server did not return any data", "default")],
                       stderr=True)
        sys.exit(errno.EINVAL)

    for node in vlist:
        name: str = deep_get(node, DictPath("metadata#name"))
        node_roles: list[str] = get_node_roles(cast(dict, node))
        if "control-plane" in node_roles or "master" in node_roles:
            ipaddresses = []
            for address in deep_get(node, DictPath("status#addresses")):
                if deep_get(address, DictPath("type"), "") == "InternalIP":
                    ipaddresses.append(deep_get(address, DictPath("address")))
            controlplanes.append((name, ipaddresses))

    return controlplanes
