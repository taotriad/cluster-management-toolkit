# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Get the list of hosts belonging to a group in the Ansible inventory.
"""

from pathlib import Path

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def ansible_get_hosts_by_group(inventory: FilePath, group: str) -> list[str]:
    """
    Get the list of hosts belonging to a group in the Ansible inventory.

        Parameters:
            inventory (FilePath): The inventory to use
            group (str): The group to return hosts for
        Returns:
            ([str]): A list of hosts
    """
    if not Path(inventory).exists():
        return []

    d = secure_read_yaml(inventory)

    return list(deep_get(d, DictPath(f"{group}#hosts"), []))
