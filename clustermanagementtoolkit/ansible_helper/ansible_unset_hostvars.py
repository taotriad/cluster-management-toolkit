# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, deep_pop, deep_set, validate_args


# Unset one or several vars for the specified host in the group all
def ansible_unset_hostvars(inventory: FilePath,
                           hosts: list[str], hostvars: list[str], **kwargs: Any) -> bool:
    """
    Unset one or several vars for the specified hosts.

        Parameters:
            inventory (FilePath): The path to the inventory
            groups (list[str]): The hosts to unset variables for
            hostvars (list[(str]): The values to unset
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
            continue

        for key in hostvars:
            # Unset the variable
            deep_pop(d, DictPath(f"all#hosts#{host}"), DictPath(key), None)
            changed = True

        if not d["all"]["hosts"][host]:
            deep_set(d, DictPath(f"all#hosts#{host}"), None)

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
