# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Get the list of groups in the Ansible inventory.
"""

from pathlib import Path

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmttypes import FilePath


def ansible_get_groups(inventory: FilePath) -> list[str]:
    """
    Get the list of groups in the Ansible inventory.

        Parameters:
            inventory (FilePath): The inventory to use
        Returns:
            ([str]): A list of groups
    """
    if not Path(inventory).exists():
        return []

    try:
        d = dict(secure_read_yaml(inventory))
    except TypeError:
        d = {}
    return list(d)
