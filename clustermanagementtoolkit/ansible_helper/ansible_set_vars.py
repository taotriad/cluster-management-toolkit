# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Set one or several values for a group in the Ansible inventory.
"""

from pathlib import Path
from typing import Any

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.ansible_helper.__ansible_create_inventory import __ansible_create_inventory  # noqa: E501

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, deep_set, validate_args


def ansible_set_vars(inventory: FilePath, group: str, values: dict, **kwargs: Any) -> bool:
    """
    Set one or several values for a group in the Ansible inventory.

        Parameters:
            inventory (FilePath): The path to the inventory
            group (str): The group to set variables for
            values (dict): The values to set
            **kwargs (dict[str, Any]): Keyword arguments
                temporary (bool): Is the inventory a tempfile?
        Returns:
            (bool): True on success, False on failure
        Raises:
            ArgumentValidationError: At least one of the arguments failed validation
    """
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)
    changed: bool = False

    validate_args(kwargs_spec={"__allof": ("inventory", "group", "values", "temporary"),
                               "inventory": {"types": (str,), "range": (1, None)},
                               "group": {"types": (str,), "range": (1, None)},
                               "values": {"types": (dict,), "range": (1, None)},
                               "temporary": {"types": (bool,)}},
                  kwargs={"inventory": inventory,
                          "group": group,
                          "values": values,
                          "temporary": temporary})

    if not Path(inventory).is_file():
        __ansible_create_inventory(inventory, overwrite=False, temporary=temporary)

    d = secure_read_yaml(inventory, temporary=temporary)

    # If the group does not exist we create it
    deep_set(d, DictPath(f"{group}#vars"),
             deep_get(d, DictPath(f"{group}#vars"), {}), create_path=True)

    for key in values:
        value_key = deep_get(values, DictPath(key))
        if key in deep_get(d, DictPath(f"{group}#vars"), {}) \
                and deep_get(d, DictPath(f"{group}#vars#{key}"), {}) == value_key:
            continue

        # Set the variable (overwriting previous value)
        deep_set(d, DictPath(f"{group}#vars#{key}"), value_key)
        changed = True

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
