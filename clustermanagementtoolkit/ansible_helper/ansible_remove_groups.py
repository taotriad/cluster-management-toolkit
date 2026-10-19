# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from pathlib import Path
import sys
from typing import Any

try:
    import ruyaml  # type: ignore[import-not-found,unused-ignore]
    ryaml = ruyaml.YAML()
    sryaml = ruyaml.YAML(typ="safe")
except ModuleNotFoundError:  # pragma: no cover
    try:
        import ruamel.yaml as ruyaml  # type: ignore[no-redef,unused-ignore]
        ryaml = ruyaml.YAML()
        sryaml = ruyaml.YAML(typ="safe")
    except ModuleNotFoundError:  # pragma: no cover
        sys.exit("ModuleNotFoundError: Could not import ruyaml/ruamel.yaml; "
                 "you may need to (re-)run `cmt-install.py` or `pip3 install ruyaml/ruamel.yaml`; "
                 "aborting.")

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, validate_args


def ansible_remove_groups(inventory: FilePath, groups: list[str], **kwargs: Any) -> bool:
    """
    Remove groups from the inventory.

        Parameters:
            inventory (FilePath): The inventory to use
            groups (list[str]): The groups to remove
            **kwargs (dict[str, Any]): Keyword arguments
                force (bool): Force allows for removal of non-empty groups
                temporary (bool): Is the inventory a tempfile?
        Returns:
            (bool): True on success, False on failure
        Raises:
            ArgumentValidationError: At least one of the arguments failed validation
    """
    force: bool = deep_get(kwargs, DictPath("force"), False)
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)

    changed = False

    validate_args(kwargs_spec={"__allof": ("inventory", "groups", "force", "temporary"),
                               "inventory": {"types": (str,), "range": (1, None)},
                               "groups": {"types": (list, tuple,), "range": (1, None)},
                               "force": {"types": (bool,)},
                               "temporary": {"types": (bool,)}},
                  kwargs={"inventory": inventory,
                          "groups": groups,
                          "force": force,
                          "temporary": temporary})

    if not Path(inventory).is_file():
        return False

    d: dict[str, Any] | ruyaml.comments.CommentedMap = {}
    tmp_d: Any = secure_read_yaml(inventory, temporary=temporary)
    if isinstance(tmp_d, (dict, ruyaml.comments.CommentedMap)):
        d = tmp_d

    for group in groups:
        if deep_get(d, DictPath(group)) is None:
            continue

        if deep_get(d, DictPath(f"{group}#hosts")) is not None and not force:
            continue

        d.pop(group)
        changed = True

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
