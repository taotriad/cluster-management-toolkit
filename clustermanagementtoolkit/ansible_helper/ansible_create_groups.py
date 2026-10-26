# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Create new groups in the Ansible inventory.
"""

from pathlib import Path
from typing import Any

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.ansible_helper.__ansible_create_inventory import __ansible_create_inventory  # noqa: E501

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def ansible_create_groups(inventory: FilePath, groups: list[str], **kwargs: Any) -> bool:
    """
    Create new groups in the Ansible inventory.

        Parameters:
            inventory (FilePath): The path to the inventory
            groups ([str]): The groups to create
            **kwargs (dict[str, Any]): Keyword arguments
                temporary (bool): Is the inventory a tempfile?
        Returns:
            (bool): True on success, False on failure
        Raises:
            TypeError: group is not a str
    """
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)

    changed: bool = False

    if groups is None or not groups:
        return True

    if not Path(inventory).is_file():
        __ansible_create_inventory(inventory, overwrite=False, temporary=temporary)

    d = secure_read_yaml(inventory, temporary=temporary)

    for group in groups:
        if not isinstance(group, str):
            raise TypeError(f"group is type: {type(group)}; expected str")
        # Group already exists; ignore
        if group in d:
            continue

        d[group] = {
            "hosts": {},
        }

        changed = True

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
