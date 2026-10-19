# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Prepare hosts to be added as nodes in a Kubernetes clusters.
"""

from typing import Any

from clustermanagementtoolkit.ansible_helper import ansible_add_hosts
from clustermanagementtoolkit.ansible_helper import ansible_print_action_summary
from clustermanagementtoolkit.ansible_helper import populate_playbooks_from_filenames

from clustermanagementtoolkit.cluster_actions.run_playbooks import run_playbooks

from clustermanagementtoolkit.cmtpaths import ANSIBLE_INVENTORY

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.networkio import scan_and_add_ssh_keys

prepare_playbooks: list[FilePath] = [
    FilePath("prepare_passwordless_ansible.yaml"),
    FilePath("prepare_node.yaml"),
]


def prepare_nodes(hosts: list[str], **kwargs: Any) -> int:
    """
    Given a list of hostnames prepare them for use as cluster nodes.

        Parameters:
            hosts ([str]): A list of hosts to prepare as nodes
            **kwargs (dict[str, Any]): Keyword arguments
                extra_values (dict): Extra values to pass to Ansible
                verbose (bool): If the results are printed, should skipped tasks be printed too?
        Returns:
            (int): 0 on success, non-zero on failure
    """
    extra_values: dict = deep_get(kwargs, DictPath("extra_values"), {})
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)

    playbooks = populate_playbooks_from_filenames(prepare_playbooks)
    ansible_print_action_summary(playbooks)
    print()

    # Create inventory entries for the hosts; existing entries are silently ignored
    ansible_add_hosts(inventory=ANSIBLE_INVENTORY, hosts=hosts, skip_all=False)

    # Add the SSH keys for the new hosts
    scan_and_add_ssh_keys(hosts)

    # Now prepare the hosts
    return run_playbooks(playbooks=playbooks, hosts=hosts,
                         extra_values=extra_values, verbose=verbose)
