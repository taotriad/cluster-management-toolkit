# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Get the Ansible inventory and return it as a dict.
"""

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

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmtpaths import ANSIBLE_INVENTORY

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get, deep_set


def ansible_get_inventory_dict() -> dict[str, Any] | ruyaml.comments.CommentedMap:
    """
    Get the Ansible inventory and return it as a dict.

        Returns:
            (dict): A dictionary with an Ansible inventory
    """
    d: dict[str, Any] | ruyaml.comments.CommentedMap = {
        "all": {
            "hosts": {},
            "vars": {},
        },
    }

    if not Path(ANSIBLE_INVENTORY).is_file():
        return d

    tmp_d: Any = secure_read_yaml(ANSIBLE_INVENTORY)
    if isinstance(tmp_d, (dict, ruyaml.comments.CommentedMap)):
        deep_set(tmp_d, DictPath("all#hosts"),
                 deep_get(tmp_d, DictPath("all#hosts"), {}), create_path=True)
        deep_set(tmp_d, DictPath("all#vars"),
                 deep_get(tmp_d, DictPath("all#vars"), {}), create_path=True)
        d = tmp_d

    return d
