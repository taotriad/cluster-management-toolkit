# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Dummy asynchronous listgetter for Ansible inventories.
"""


def get_inventory_list() -> None:
    """
    Dummy function used as a cookie for inventory list.
    """
    return
