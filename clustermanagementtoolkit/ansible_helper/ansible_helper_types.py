# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Configuration for Ansible.
"""

from typing import ClassVar


# pylint: disable-next=too-few-public-methods
class AnsibleConfiguration:
    """
    Configuration for Ansible.
    """
    ansible_forks: ClassVar[int] = 10
    ansible_password: ClassVar[str | None] = None
    ansible_user: ClassVar[str | None] = None
    disable_strict_host_key_checking: ClassVar[bool] = False
    save_logs: ClassVar[bool] = False
