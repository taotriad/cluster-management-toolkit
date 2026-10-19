# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Ansible-related helpers.
"""

# pylint: disable=line-too-long
from clustermanagementtoolkit.ansible_helper.__ansible_create_inventory import __ansible_create_inventory  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_add_hosts import ansible_add_hosts
from clustermanagementtoolkit.ansible_helper.ansible_create_groups import ansible_create_groups
from clustermanagementtoolkit.ansible_helper.ansible_delete_log import ansible_delete_log
from clustermanagementtoolkit.ansible_helper.ansible_extract_failure import ansible_extract_failure
from clustermanagementtoolkit.ansible_helper.ansible_get_groups import ansible_get_groups
from clustermanagementtoolkit.ansible_helper.ansible_get_groups_by_host import ansible_get_groups_by_host  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_get_hosts_by_group import ansible_get_hosts_by_group  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_get_inventory_dict import ansible_get_inventory_dict  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_get_inventory_pretty import ansible_get_inventory_pretty  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_get_logs import ansible_get_logs
from clustermanagementtoolkit.ansible_helper.ansible_ping import ansible_ping
from clustermanagementtoolkit.ansible_helper.ansible_print_action_summary import ansible_print_action_summary  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_print_play_results import ansible_print_play_results  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_print_task_results import ansible_print_task_results  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_remove_groups import ansible_remove_groups
from clustermanagementtoolkit.ansible_helper.ansible_remove_hosts import ansible_remove_hosts
from clustermanagementtoolkit.ansible_helper.ansible_results_extract import ansible_results_extract
from clustermanagementtoolkit.ansible_helper.ansible_run_playbook import ansible_run_playbook
from clustermanagementtoolkit.ansible_helper.ansible_run_playbook_on_selection import ansible_run_playbook_on_selection  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_set_groupvars import ansible_set_groupvars
from clustermanagementtoolkit.ansible_helper.ansible_set_hostvars import ansible_set_hostvars
from clustermanagementtoolkit.ansible_helper.ansible_set_vars import ansible_set_vars
from clustermanagementtoolkit.ansible_helper.ansible_unset_groupvars import ansible_unset_groupvars
from clustermanagementtoolkit.ansible_helper.ansible_unset_hostvars import ansible_unset_hostvars
from clustermanagementtoolkit.ansible_helper.get_playbook_path import get_playbook_path
from clustermanagementtoolkit.ansible_helper.populate_playbooks_from_filenames import populate_playbooks_from_filenames  # noqa: E501
from clustermanagementtoolkit.ansible_helper.ansible_helper_types import AnsibleConfiguration
# pylint: enable=line-too-long

__all__ = [
    "AnsibleConfiguration",
    "__ansible_create_inventory",
    "ansible_add_hosts",
    "ansible_create_groups",
    "ansible_delete_log",
    "ansible_extract_failure",
    "ansible_get_groups",
    "ansible_get_groups_by_host",
    "ansible_get_hosts_by_group",
    "ansible_get_inventory_dict",
    "ansible_get_inventory_pretty",
    "ansible_get_logs",
    "ansible_ping",
    "ansible_print_action_summary",
    "ansible_print_play_results",
    "ansible_print_task_results",
    "ansible_remove_groups",
    "ansible_remove_hosts",
    "ansible_results_extract",
    "ansible_run_playbook",
    "ansible_run_playbook_on_selection",
    "ansible_set_groupvars",
    "ansible_set_hostvars",
    "ansible_set_vars",
    "ansible_unset_groupvars",
    "ansible_unset_hostvars",
    "get_playbook_path",
    "populate_playbooks_from_filenames",
]
