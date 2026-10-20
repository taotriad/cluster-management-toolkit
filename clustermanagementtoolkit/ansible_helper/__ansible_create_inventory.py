# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Create a new Ansible inventory at the path given if no inventory exists.
"""

from pathlib import Path
from typing import Any

from clustermanagementtoolkit.ansible_helper.ansible_helper_types import AnsibleConfiguration

from clustermanagementtoolkit.cmtio import secure_mkdir

from clustermanagementtoolkit.cmtio_yaml import secure_write_yaml

from clustermanagementtoolkit.cmtpaths import ANSIBLE_DIR

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get, deep_set


def __ansible_create_inventory(inventory: FilePath, **kwargs: Any) -> bool:
    """
    Create a new Ansible inventory at the path given if no inventory exists.

        Parameters:
            inventory (FilePath): A path where to create a new inventory (if non-existing)
            **kwargs (dict[str, Any]): Keyword arguments
                overwrite (bool): True: Overwrite the existing inventory?
                temporary (bool): Is the inventory a tempfile?
        Return:
            (bool): True if inventory was created, False if nothing was done
    """
    overwrite: bool = deep_get(kwargs, DictPath("overwrite"), False)
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)

    if not isinstance(inventory, (FilePath, str)):
        raise TypeError(f"inventory is type: {type(inventory)}, expected str")
    if not isinstance(overwrite, bool):
        raise TypeError(f"inventory is type: {type(overwrite)}, expected bool")

    # Do not create anything if the inventory exists;
    # unless overwrite is set
    if Path(inventory).exists() and not overwrite:
        return False

    # If the ansible directory does not exist, create it
    secure_mkdir(ANSIBLE_DIR, permissions=0o755, exit_on_failure=True)

    # Create the basic yaml structure that we will write later on
    d: dict = {
        "all": {
            "hosts": {},
            # Workaround for Ubuntu 18.04 and various other older operating systems
            # that have python3 installed, but not as default.
            "vars": {
                "ansible_python_interpreter": "/usr/bin/python3",
            }
        }
    }

    if (ansible_user := AnsibleConfiguration.ansible_user) is not None:
        deep_set(d, DictPath("all#vars#ansible_user"), ansible_user, create_path=True)

    if (ansible_password := AnsibleConfiguration.ansible_password) is not None:
        deep_set(d, DictPath("all#vars#ansible_ssh_pass"), ansible_password, create_path=True)

    if AnsibleConfiguration.disable_strict_host_key_checking is True:
        deep_set(d, DictPath("ansible_ssh_common_args"), "-o StrictHostKeyChecking=no",
                 create_path=True)

    secure_write_yaml(inventory, d, permissions=0o600, replace_empty=True, temporary=temporary)

    return True
