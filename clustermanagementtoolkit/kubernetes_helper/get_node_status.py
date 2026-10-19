# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the status for a node.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get


def get_node_status(node: dict) -> tuple[str, StatusGroup, list[tuple[str, str]], list[dict]]:
    """
    Given a node dict, extract the node status.

        Parameters:
            node (dict): A dict with node information
        Returns:
            (status, status_group, taints, full_taints):
                status (str): A string representation of the node status
                status_group (StatusGroup): An enum representation of the node status
                taints (list[(str, str)]): A list of curated taints in tuple format
                full_taints (list[dict]): The full list of taints in dict format
    """
    status = "Unknown"
    status_group = StatusGroup.UNKNOWN
    taints = []
    full_taints = deep_get(node, DictPath("spec#taints"), [])

    for condition in deep_get(node, DictPath("status#conditions"), []):
        if deep_get(condition, DictPath("type")) == "Ready":
            condition_status = deep_get(condition, DictPath("status"))
            if condition_status == "True":
                status = "Ready"
                status_group = StatusGroup.OK
            elif condition_status == "Unknown":
                status = "Unreachable"
                status_group = StatusGroup.NOT_OK
            else:
                status = "NotReady"
                status_group = StatusGroup.NOT_OK

    for nodetaint in deep_get(node, DictPath("spec#taints"), []):
        key = deep_get(nodetaint, DictPath("key"))
        if key == "node-role.kubernetes.io/master":
            key = "node-role.kubernetes.io/control-plane"
        effect = deep_get(nodetaint, DictPath("effect"))

        # Control Plane having scheduling disabled
        # is expected behaviour and does not need
        # any form of highlighting
        if deep_get(nodetaint, DictPath("effect")) == "NoSchedule":
            if key == "node-role.kubernetes.io/control-plane":
                taints.append(("control-plane", effect))
                continue

            key = key.removeprefix("node.kubernetes.io/")
            taints.append((key, effect))

            # If status is already "worse" than OK,
            # we do not override it.
            # Scheduling being disabled is not an error,
            # but it is worth highlighting
            if status_group == StatusGroup.OK:
                status_group = StatusGroup.ADMIN
        else:
            key = key.removeprefix("node.kubernetes.io/")
            taints.append((key, effect))

    return status, status_group, taints, full_taints
