# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Run an Ansible playbook on selected hosts.
"""

import errno
from typing import Any

from clustermanagementtoolkit.ansible_helper.ansible_run_playbook import ansible_run_playbook
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.ansible_helper.ansible_get_inventory_dict import ansible_get_inventory_dict  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_helper_types import AnsibleConfiguration

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def ansible_run_playbook_on_selection(playbook: FilePath,
                                      selection: list[str], **kwargs: Any) -> tuple[int, dict]:
    """
    Run an Ansible playbook on selected hosts.

        Parameters:
            playbook (FilePath): The playbook to run
            selection ([str]): The hosts to run the play on
            kwargs (dict):
                values (dict): Extra values to set for the hosts
                verbose (bool): Output status updates for every new Ansible event
                quiet (bool): Disable console output
                save_logs (bool | None): Override the save_logs variable in AnsibleConfiguration
        Returns:
            ((int, dict)):
                (int): The result from ansible_run_playbook();
                       -errno.ENOENT if the inventory is missing or empty
                (dict): The results of the run
    """
    # If ansible_ssh_pass system variable is not set, and ansible_sudo_pass is set,
    # we set ansible_ssh_pass to ansible_become_pass; on systems where we already have a host key
    # this will be ignored; the same goes for groups or hosts where ansible_ssh_pass is set,
    # since group and host vars take precedence over system vars.
    #
    # This is mainly for the benefit of making the prepare_host task possible to run without
    # encouraging permanent use of ansible_{ssh,sudo,become}_pass.
    # Ideally these variables should only be needed once; when preparing the host; after that
    # we will use passwordless sudo and ssh hostkeys.
    #
    # Also, if ansible_user is not set ansible will implicitly use the local user. Pass this
    # as ansible user to make scripts that tries to access ansible_user function properly.
    d = ansible_get_inventory_dict()

    if not d:
        return -errno.ENOENT, {}

    values: dict[str, Any] = deep_get(kwargs, DictPath("values"), {})
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)
    quiet: bool = deep_get(kwargs, DictPath("quiet"), True)
    save_logs: bool | None = deep_get(kwargs, DictPath("save_logs"))

    if "ansible_sudo_pass" in values and "ansible_become_pass" not in values:
        values["ansible_become_pass"] = values["ansible_sudo_pass"]
    if "ansible_become_pass" in values and "ansible_ssh_pass" not in d["all"]["vars"]:
        values["ansible_ssh_pass"] = values["ansible_become_pass"]
    if "ansible_user" not in d["all"]["vars"]:
        values["ansible_user"] = AnsibleConfiguration.ansible_user

    for key, value in values.items():
        d["all"]["vars"][key] = value

    d["selection"] = {
        "hosts": {}
    }

    for host in selection:
        d["selection"]["hosts"][host] = {}

    return ansible_run_playbook(playbook, inventory=d, verbose=verbose, quiet=quiet,
                                save_logs=save_logs)
