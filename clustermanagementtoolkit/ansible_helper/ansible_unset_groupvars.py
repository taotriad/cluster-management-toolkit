# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Unset one or several vars for the specified groups in the Ansible inventory.
"""

from typing import Any

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, deep_pop, validate_args


# Unset one or several vars in the specified groups
def ansible_unset_groupvars(inventory: FilePath,
                            groups: list[str], groupvars: list[str], **kwargs: Any) -> bool:
    """
    Unset one or several vars for the specified groups in the Ansible inventory.

        Parameters:
            inventory (FilePath): The path to the inventory
            groups (list[str]): The groups to unset variables for
            groupvars (list[(str]): The values to unset
            **kwargs (dict[str, Any]): Keyword arguments
                temporary (bool): Is the inventory a tempfile?
        Returns:
            (bool): True on success, False on failure
        Raises:
            ArgumentValidationError: At least one of the arguments failed validation
    """
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)

    changed = False

    validate_args(kwargs_spec={"__allof": ("inventory", "groups", "groupvars", "temporary"),
                               "inventory": {"types": (str,), "range": (1, None)},
                               "groups": {"types": (list, dict), "range": (1, None)},
                               "groupvars": {"types": (list, dict), "range": (1, None)},
                               "temporary": {"types": (bool,)}},
                  kwargs={"inventory": inventory,
                          "groups": groups,
                          "groupvars": groupvars,
                          "temporary": temporary})

    d = secure_read_yaml(inventory, temporary=temporary)

    for group in groups:
        # Silently ignore non-existing groups
        if group not in d:
            continue

        if d[group] is None:
            continue

        if d[group].get("vars") is None:
            continue

        for key in groupvars:
            # Unset the variable
            deep_pop(d, DictPath(f"{group}#vars"), DictPath(key), None)
            changed = True

        # If the group no longer has any vars set,
        # remove vars
        if not d[group]["vars"]:
            deep_pop(d, DictPath(group), DictPath("vars"), None)

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
