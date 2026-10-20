# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Add hosts to the ansible inventory; if the inventory does not exist, create it.
"""

from pathlib import Path
import sys
from typing import Any, cast

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

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.ansible_helper.__ansible_create_inventory import __ansible_create_inventory  # noqa: E501

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, deep_set, validate_args


def ansible_add_hosts(inventory: FilePath, hosts: list[str], **kwargs: Any) -> bool:
    """
    Add hosts to the Ansible inventory; if the inventory does not exist, create it.

        Parameters:
            inventory (FilePath): The path to the inventory
            hosts (list[str]): The hosts to add to the inventory
            **kwargs (dict[str, Any]): Keyword arguments
                group (str): The group to add the hosts to
                skip_all (bool): If True we do not create a new inventory if it does not exist
                temporary (bool): Is the inventory a tempfile?
        Returns:
            (bool): True on success, False on failure
        Raises:
            ArgumentValidationError: At least one of the arguments failed validation
    """
    group: str = deep_get(kwargs, DictPath("group"), "")
    skip_all: bool = deep_get(kwargs, DictPath("skip_all"), False)
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)

    changed = False

    validate_args(kwargs_spec={"__allof": ("inventory", "hosts", "group", "skip_all", "temporary"),
                               "inventory": {"types": (str,), "range": (1, None)},
                               "hosts": {"types": (list, tuple,), "range": (1, None)},
                               "group": {"types": (str,), "range": (0, None)},
                               "skip_all": {"types": (bool,)},
                               "temporary": {"types": (bool,)}},
                  kwargs={"inventory": inventory,
                          "hosts": hosts,
                          "group": group,
                          "skip_all": skip_all,
                          "temporary": temporary})

    d: dict[str, Any] | ruyaml.comments.CommentedMap = {}

    tmp_d: Any = None

    # The inventory does not exist; if the user specified skip_all
    # we do not mind, otherwise we need to create it
    if not Path(inventory).is_file():
        if skip_all and group != "all":
            changed = True
        else:
            __ansible_create_inventory(inventory, overwrite=False)
            tmp_d = secure_read_yaml(inventory, temporary=temporary)
    else:
        tmp_d = secure_read_yaml(inventory, temporary=temporary)
    if isinstance(tmp_d, (dict, ruyaml.comments.CommentedMap)):
        d = tmp_d

    for host in hosts:
        # Kubernetes doesn't like uppercase hostnames
        host = host.lower()

        # All nodes go into the "hosts" group of the "all" group,
        # no matter if the caller also supplies a group, unless
        # skip_all has been specified; the exception being
        # if the group is all
        #
        # Do not add a host that already exists in all;
        # that will wipe its vars
        if not skip_all and group != "all":
            if d["all"]["hosts"] is None:
                d["all"]["hosts"] = {}
            if host not in cast(list, d["all"]["hosts"]):
                d = cast(dict, d)
                d["all"]["hosts"][host] = {}
                changed = True

        # If the group does not exist, create it--we currently do not support
        # nested groups, node vars, or anything like that.
        #
        # We do not want to overwrite groups.
        if group not in ("", "all") and host not in deep_get(d, DictPath(f"{group}#hosts"), {}):
            deep_set(d, DictPath(f"{group}#hosts#{host}"), {}, create_path=True)
            changed = True

    if changed:
        secure_write_yaml(inventory, d, permissions=0o600,
                          replace_empty=True, replace_null=True, temporary=temporary)

    return True
