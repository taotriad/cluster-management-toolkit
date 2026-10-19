# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any
from collections.abc import Sequence

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, validate_args


def ansible_set_groupvars(inventory: FilePath,
                          groups: list[str],
                          groupvars: Sequence[tuple[str, str | int]], **kwargs: Any) -> bool:
    """
    Set one or several vars for the specified groups.

        Parameters:
            inventory (FilePath): The path to the inventory
            groups (list[str]): The groups to set variables for
            groupvars (list[(str, str|int)]): The values to set
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
            d[group] = {}

        if d[group].get("vars") is None:
            d[group]["vars"] = {}

        for key, value in groupvars:
            # Set the variable (overwriting previous value)
            d[group]["vars"][key] = value
            changed = True

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
