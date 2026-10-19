# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, deep_pop, validate_args


# Remove hosts from ansible groups
def ansible_remove_hosts(inventory: FilePath, hosts: list[str], **kwargs: Any) -> bool:
    """
    Remove hosts from the inventory.

        Parameters:
            inventory (FilePath): The inventory to use
            hosts (list[str]): The hosts to remove
            **kwargs (dict[str, Any]): Keyword arguments
                group (str): The group to remove the hosts from
                temporary (bool): Is the inventory a tempfile?
        Returns:
            (bool): True on success, False on failure
        Raises:
            ArgumentValidationError: At least one of the arguments failed validation
    """
    group: str = deep_get(kwargs, DictPath("group"), "")
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)

    changed = False

    validate_args(kwargs_spec={"__allof": ("inventory", "hosts", "group", "temporary"),
                               "inventory": {"types": (str,), "range": (1, None)},
                               "hosts": {"types": (list, tuple,), "range": (1, None)},
                               "group": {"types": (str,), "range": (0, None)},
                               "temporary": {"types": (bool,)}},
                  kwargs={"inventory": inventory,
                          "hosts": hosts,
                          "group": group,
                          "temporary": temporary})

    d = secure_read_yaml(inventory, temporary=temporary)

    for host in hosts:
        if host in deep_get(d, DictPath(f"{group}#hosts"), {}):
            deep_pop(d, DictPath(f"{group}#hosts"), DictPath(host), None)
            changed = True

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
