# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
This file contains helpers that provide an obj for use in info views,
for cases where the obj provided from the list view is not sufficient.
"""

from collections.abc import Callable

from clustermanagementtoolkit.objgetters.objgetter_ansible_facts import objgetter_ansible_facts
from clustermanagementtoolkit.objgetters.objgetter_ansible_log import objgetter_ansible_log
from clustermanagementtoolkit.objgetters.objgetter_journalctl_log import objgetter_journalctl_log


__all__ = [
    "objgetter_ansible_facts",
    "objgetter_ansible_log",
    "objgetter_journalctl_log",
]


# Objgetters acceptable for direct use in view files
objgetter_allowlist: dict[str, Callable] = {
    "objgetter_ansible_facts": objgetter_ansible_facts,
    "objgetter_ansible_log": objgetter_ansible_log,
    "objgetter_journalctl_log": objgetter_journalctl_log,
}
