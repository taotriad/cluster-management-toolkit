# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Ansible ping all selected hosts.
"""

from typing import Any

from clustermanagementtoolkit.ansible_helper.ansible_extract_failure import ansible_extract_failure
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.ansible_helper.ansible_get_hosts_by_group import ansible_get_hosts_by_group  # noqa: E501
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.ansible_helper.ansible_run_playbook_on_selection import ansible_run_playbook_on_selection  # noqa: E501
from clustermanagementtoolkit.ansible_helper.get_playbook_path import get_playbook_path
from clustermanagementtoolkit.ansible_helper.ansible_helper_types import AnsibleConfiguration

from clustermanagementtoolkit.cmtpaths import ANSIBLE_INVENTORY

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import validate_args


def ansible_ping(selection: list[str] | None = None, **kwargs: Any) -> list[tuple[str, str]]:
    """
    Ansible ping all selected hosts.

        Parameters:
            selection ([str]): A list of hostnames
            **kwargs (dict[str, Any]): Keyword arguments
                verbose (bool): Should status include stderr_lines?
        Returns:
            [(str, str)]: The status of the pinged hosts
    """
    save_logs_tmp: bool = getattr(AnsibleConfiguration, "save_logs", False)
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)
    AnsibleConfiguration.save_logs = False

    host_status = []

    if selection is None:
        selection = ansible_get_hosts_by_group(ANSIBLE_INVENTORY, "all")
    else:
        validate_args(kwargs_spec={"__allof": ("selection",), "selection": {"types": (list,)}},
                      kwargs={"selection": selection})

    playbook_path = get_playbook_path(FilePath("ping.yaml"))
    _retval, ansible_results = ansible_run_playbook_on_selection(playbook_path,
                                                                 selection=selection, quiet=False)

    for host in ansible_results:
        for task in deep_get(ansible_results, DictPath(host), []):
            unreachable = deep_get(task, DictPath("unreachable"))
            skipped = deep_get(task, DictPath("skipped"))
            stderr_lines: list[str] = deep_get(task, DictPath("stderr_lines"), [])
            retval = deep_get(task, DictPath("retval"))
            status = ansible_extract_failure(retval,
                                             stderr_lines,
                                             skipped=skipped, unreachable=unreachable)
            if stderr_lines and verbose:
                status += " (" + "\\n".join(stderr_lines) + ")"
            host_status.append((host, status))
    AnsibleConfiguration.save_logs = save_logs_tmp

    return host_status
