# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Asynchronous listgetter for Kubernetes context-lists.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-locals
def get_context_list(**kwargs: Any) -> tuple[list[dict], list[str]]:
    """
    Get the list of Kubernetes contexts.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): The KubernetesHelper object to use (required)
                tag_prefix (str): The prefix to use for the tagged list item (optional)
        Returns:
            ([dict], [str]):
                [dict]: The list of context information
                [str]: The list of API-servers for those contexts
        Raises:
            ProgrammingError: Function called without kubernetes_helper
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")

    vlist = []
    hosts = []

    context_list = kh.list_contexts()
    tag_prefix = deep_get(kwargs, DictPath("tag_prefix"), "✓ ")

    inventory_dict: dict[str, Any] = {
        "all": {
            "hosts": {},
        }
    }

    server_address_regex = re.compile(r"^(https?://)(.+)(:\d+)$")

    for is_current_context, name, cluster, authinfo, namespace, server in context_list:
        if is_current_context:
            current = tag_prefix
        else:
            current = "".ljust(len(tag_prefix))

        server_address = ""
        if (re_tmp := server_address_regex.match(server)) is not None:
            server_address = re_tmp[2]
            hosts.append(server_address)

        vlist.append({
            "current": current,
            "name": name,
            "cluster": cluster,
            "authinfo": authinfo,
            "namespace": namespace,
            "server": server,
            "server_address": server_address,
            # Before we ping the hosts their status is unknown
            "status": "UNKNOWN",
        })

        if server_address:
            inventory_dict["all"]["hosts"][server_address] = {}
            inventory_dict["all"]["hosts"][server_address]["status"] = "UNKNOWN"
            inventory_dict["all"]["vars"] = {}

    return vlist, hosts
