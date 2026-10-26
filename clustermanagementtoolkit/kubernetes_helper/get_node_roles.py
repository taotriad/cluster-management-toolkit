# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of the roles that a node belongs to.
"""

import re

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_node_roles(node: dict) -> list[str]:
    """
    Get a list of the roles that the node belongs to.

        Parameters:
            node (dict): The node object
        Returns:
            ([str]): The roles that the node belongs to
    """
    roles: list[str] = []

    node_role_regex = re.compile(r"^node-role\.kubernetes\.io/(.*)")

    for label in deep_get(node, DictPath("metadata#labels"), {}).items():
        tmp = node_role_regex.match(label[0])

        if tmp is None:
            continue

        role = tmp[1]

        if role not in roles:
            roles.append(role)

    return roles
