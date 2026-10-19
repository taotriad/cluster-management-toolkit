# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.ansible_helper import AnsibleConfiguration
from clustermanagementtoolkit.ansible_helper import ansible_print_play_results
from clustermanagementtoolkit.ansible_helper import ansible_run_playbook_on_selection
from clustermanagementtoolkit.ansible_helper import get_playbook_path

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint
from clustermanagementtoolkit.ansithemeprint import ansithemestr_join_list

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def run_playbook(playbookpath: FilePath, hosts: list[str], **kwargs: Any) -> tuple[int, dict]:
    """
    Run a playbook.

        Parameters:
            playbookpath (FilePath): A path to the playbook to run
            hosts (list[str]): A list of hosts to run the playbook on
            **kwargs (dict[str, Any]): Keyword arguments
                extra_values (dict): A dict of values to set before running the playbook
                quiet (bool): Should the results of the run be printed?
                verbose (bool): If the results are printed, should skipped tasks be printed too?
        Returns:
            ((int, dict)):
                (int): The return value from ansible_run_playbook_on_selection()
                (dict): A dict with the results from the run
    """
    extra_values: dict = deep_get(kwargs, DictPath("extra_values"), {})
    quiet: bool = deep_get(kwargs, DictPath("quiet"), False)
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)

    # Set necessary Ansible keys before running playbooks
    http_proxy: str = deep_get(cmtlib.cmtconfig, DictPath("Network#http_proxy"), "")
    https_proxy: str = deep_get(cmtlib.cmtconfig, DictPath("Network#https_proxy"), "")
    no_proxy: str = deep_get(cmtlib.cmtconfig, DictPath("Network#no_proxy"), "")

    use_proxy = "no"
    if http_proxy or https_proxy:
        use_proxy = "yes"

    values = {
        "http_proxy": http_proxy,
        "https_proxy": https_proxy,
        "no_proxy": no_proxy,
        "use_proxy": use_proxy,
    }
    merged_values = {**values, **extra_values}

    retval, ansible_results = \
        ansible_run_playbook_on_selection(playbookpath, selection=hosts, values=merged_values,
                                          verbose=verbose, quiet=quiet)

    if not quiet:
        ansible_print_play_results(retval, ansible_results, verbose=verbose)

    return retval, ansible_results


# pylint: disable-next=too-many-locals
def check_control_plane(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether a host is suitable to be used as a control plane.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
        Returns:
            (bool, int, int, int, int):
                (bool): Is this error severe enough that we should abort immediately?
                critical (int): The new count of critical severity security issues
                error (int): The new count of error severity security issues
                warning (int): The new count of warning severity security issues
                note (int): The new count of note severity security issues
    """
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)

    abort = False

    # The host(s) to check
    hosts = deep_get(kwargs, DictPath("hosts"), [])
    playbookpath = get_playbook_path(FilePath("preflight_check.yaml"))

    ansithemeprint([ANSIThemeStr("[Checking whether ", "phase")]
                   + ansithemestr_join_list(hosts, formatting="hostname")
                   + [ANSIThemeStr(" are suitable as control plane(s)]", "phase")])

    extra_values = {
        "ansible_become_pass": AnsibleConfiguration.ansible_password,
        "ansible_ssh_pass": AnsibleConfiguration.ansible_password,
        "role": "control-plane",
    }

    _retval, ansible_results = run_playbook(playbookpath, hosts=hosts, extra_values=extra_values)

    for host, host_results in ansible_results.items():
        ansible_os_family = ""
        for taskdata in host_results:
            taskname = str(deep_get(taskdata, DictPath("task"), ""))

            if taskname == "Gathering Facts":
                ansible_os_family = deep_get(taskdata,
                                             DictPath("ansible_facts#ansible_os_family"), "")
                continue

            if taskname == "Checking whether the host runs an OS supported for control planes" \
                    and deep_get(taskdata, DictPath("retval")) != 0:
                abort = True
                critical += 1
                ansithemeprint([ANSIThemeStr("  ", "default"),
                                ANSIThemeStr("Critical", "critical"),
                                ANSIThemeStr(":", "default")], stderr=True)
                ansithemeprint([ANSIThemeStr("    Unsupported Operating System ",
                                             "default"),
                                ANSIThemeStr(f"{ansible_os_family}", "programname"),
                                ANSIThemeStr("; currently the only supported OS families",
                                             "default")], stderr=True)
                ansithemeprint([ANSIThemeStr("    for control planes are ", "default"),
                                ANSIThemeStr("Debian", "programname"),
                                ANSIThemeStr(" and ", "default"),
                                ANSIThemeStr("Red Hat", "programname"),
                                ANSIThemeStr("; aborting.\n", "default")], stderr=True)
                break

            if taskname == "Check whether the host is a Kubernetes control plane" \
                    and deep_get(taskdata, DictPath("retval")) != 0:
                abort = True
                critical += 1
                ansithemeprint([ANSIThemeStr("  ", "default"),
                                ANSIThemeStr("Critical", "critical"),
                                ANSIThemeStr(":", "default")])
                ansithemeprint([ANSIThemeStr("    Host ", "default"),
                                ANSIThemeStr(f"{host}", "hostname"),
                                ANSIThemeStr(" seems to already be running a Kubernetes "
                                             "API-server; aborting.\n",
                                             "default")], stderr=True)
                break

            if taskname == "Check whether the host is a Kubernetes node" \
                    and deep_get(taskdata, DictPath("retval")) != 0:
                abort = True
                critical += 1
                ansithemeprint([ANSIThemeStr("  ", "default"),
                                ANSIThemeStr("Critical", "critical"),
                                ANSIThemeStr(":", "default")], stderr=True)
                ansithemeprint([ANSIThemeStr("    Host ", "default"),
                                ANSIThemeStr(f"{host}", "hostname"),
                                ANSIThemeStr(" seems to already have a running kubelet; "
                                             "aborting.\n", "default")], stderr=True)
                break
    if not abort:
        print()

    return abort, critical, error, warning, note
