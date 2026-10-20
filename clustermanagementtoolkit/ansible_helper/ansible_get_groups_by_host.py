# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given an Ansible inventory, returns the groups a host belongs to.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get, validate_args


def ansible_get_groups_by_host(inventory_dict: dict, host: str) -> list[str]:
    """
    Given an Ansible inventory, returns the groups a host belongs to.

        Parameters:
            inventory_dict (dict): An Ansible inventory
            host (str): The host to return groups for
        Returns:
            ([str]): The list of groups the host belongs to
        Raises:
            ArgumentValidationError: At least one of the arguments failed validation
    """
    validate_args(kwargs_spec={"__allof": ("inventory_dict", "host"),
                               "inventory_dict": {"types": (dict,)},
                               "host": {"types": (str,), "range": (1, None)}},
                  kwargs={"inventory_dict": inventory_dict, "host": host})

    groups = []

    for group, group_data in inventory_dict.items():
        if host in deep_get(group_data, DictPath("hosts"), {}):
            groups.append(group)

    return groups
