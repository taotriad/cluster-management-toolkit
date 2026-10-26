# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Set one or several vars for the specified hosts in the Ansible inventory.
"""

from typing import Any
from collections.abc import Sequence

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, validate_args


# Set one or several vars for hosts in the group all
def ansible_set_hostvars(inventory: FilePath,
                         hosts: list[str],
                         hostvars: Sequence[tuple[str, str | int]], **kwargs: Any) -> bool:
    """
    Set one or several vars for the specified hosts in the Ansible inventory.

        Parameters:
            inventory (FilePath): The path to the inventory
            groups (list[str]): The hosts to set variables for
            hostvars (list[(str, str|int)]): The values to set
            **kwargs (dict[str, Any]): Keyword arguments
                temporary (bool): Is the inventory a tempfile?
        Returns:
            (bool): True on success, False on failure
        Raises:
            ArgumentValidationError: At least one of the arguments failed validation
    """
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)

    changed = False

    validate_args(kwargs_spec={"__allof": ("inventory", "hosts", "hostvars", "temporary"),
                               "inventory": {"types": (str,), "range": (1, None)},
                               "hosts": {"types": (list, dict), "range": (1, None)},
                               "hostvars": {"types": (list, dict), "range": (1, None)},
                               "temporary": {"types": (bool,)}},
                  kwargs={"inventory": inventory,
                          "hosts": hosts,
                          "hostvars": hostvars,
                          "temporary": temporary})

    d = secure_read_yaml(inventory, temporary=temporary)

    for host in hosts:
        # Silently ignore non-existing hosts
        if host not in d["all"]["hosts"]:
            continue

        if d["all"]["hosts"][host] is None:
            d["all"]["hosts"][host] = {}

        for key, value in hostvars:
            # Set the variable (overwriting previous value)
            d["all"]["hosts"][host][key] = value
            changed = True

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
