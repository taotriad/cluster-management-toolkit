# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Run an Ansible playbook.
"""

import errno
import sys
from typing import Any

from clustermanagementtoolkit.ansible_helper import ansible_print_play_results
from clustermanagementtoolkit.ansible_helper import ansible_run_playbook_on_selection

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtlib import get_latest_upstream_version

from clustermanagementtoolkit.cmtpaths import ANSIBLE_INVENTORY

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def run_playbook(playbookpath: FilePath, hosts: list[str], extra_values: dict | None = None,
                 quiet: bool = False, verbose: bool = False) -> tuple[int, dict]:
    """
    Run an Ansible playbook.

        Parameters:
            playbookpath (FilePath): A path to the playbook to run
            hosts ([str]): A list of hosts to run the playbook on
            extra_values (dict): A dict of values to set before running the playbook
            quiet (bool): Should the results of the run be printed? [unused]
            verbose (bool): If the results are printed, should skipped tasks be printed too?
        Returns:
            (int): The return value from ansible_run_playbook_on_selection()
            (dict): A dict with the results from the run
    """
    # The first patch revision that isn't available from the new repositories is 1.24.0,
    # but anything older than 1.32.0 is signed with a key that has expired, so only
    # include 1.32.0 and newer; the old repository is no longer usable.
    if (kubernetes_upstream_version := get_latest_upstream_version("kubernetes")) is None:
        ansithemeprint([ANSIThemeStr("Error", "error"),
                        ANSIThemeStr(": Could not get the latest upstream Kubernetes version; ",
                                     "default"),
                        ANSIThemeStr("this is either a network error or a bug; aborting.",
                                     "default")], stderr=True)
        sys.exit(errno.ENOENT)

    # Split the version tuple
    _upstream_major, upstream_minor, _rest = kubernetes_upstream_version.split(".")
    minor_versions = []
    for minor_version in range(32, int(upstream_minor) + 1):
        minor_versions.append(f"{minor_version}")

    values = {
        "minor_versions": minor_versions,
    }
    if extra_values:
        merged_values = {**values, **extra_values}
    else:
        merged_values = {**values}

    retval, ansible_results = \
        ansible_run_playbook_on_selection(playbookpath, selection=hosts,
                                          values=merged_values, quiet=False)
    if retval == -errno.ENOENT and not ansible_results:
        ansithemeprint([ANSIThemeStr("Error", "error"),
                        ANSIThemeStr(": ", "default"),
                        ANSIThemeStr(f"{ANSIBLE_INVENTORY}", "path"),
                        ANSIThemeStr(" is either empty or missing; aborting.", "default")],
                       stderr=True)
        sys.exit(errno.ENOENT)

    if not quiet:
        ansible_print_play_results(retval, ansible_results, verbose=verbose)
        print()

    return retval, ansible_results


def run_playbooks(playbooks: list[tuple[list[ANSIThemeStr], FilePath]], **kwargs: Any) -> int:
    """
    Run a set of Ansible playbooks.

        Parameters:
            playbooks ([([ANSIThemeStr], FilePath)]): A list of playbooks
            **kwargs (dict[str, Any]): Keyword arguments
                hosts (str): The hosts to run the playbooks on
                extra_values (dict): Variables to set before running the playbooks
                verbose (bool): If the results are printed, should skipped tasks be printed too?
        Returns:
            (int): 0 on success, non-zero on failure
    """
    hosts: list[str] | None = deep_get(kwargs, DictPath("hosts"))
    extra_values: dict | None = deep_get(kwargs, DictPath("extra_values"))
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)

    if not playbooks or hosts is None:
        return 0

    for string, playbookpath in playbooks:
        ansithemeprint(string)
        retval, _ansible_results = \
            run_playbook(playbookpath, hosts=hosts,
                         extra_values=extra_values, verbose=verbose)

        # We do not want to continue executing playbooks if the first one failed
        if retval != 0:
            break

    return retval
