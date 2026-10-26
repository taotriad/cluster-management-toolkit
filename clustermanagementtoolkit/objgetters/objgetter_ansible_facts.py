# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return an object constructed from Ansible facts.
"""

from clustermanagementtoolkit.ansible_helper import ansible_run_playbook_on_selection
from clustermanagementtoolkit.ansible_helper import get_playbook_path

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def objgetter_ansible_facts(obj: dict) -> dict:
    """
    Get an obj by using Ansible facts.

        Parameters:
            obj (dict): The obj to use as reference
        Returns:
            (dict): An ansible facts object
    """
    hostname = deep_get(obj, DictPath("name"), "")
    get_facts_path = get_playbook_path(FilePath("get_facts.yaml"))
    retval, ansible_results = ansible_run_playbook_on_selection(get_facts_path, [hostname])
    if retval != 0:
        return {}

    ar = {}

    for result in deep_get(ansible_results, DictPath(hostname), []):
        if deep_get(result, DictPath("task"), "") == "Gathering host facts":
            ar = deep_get(result, DictPath("ansible_facts"))
            break
    return ar
