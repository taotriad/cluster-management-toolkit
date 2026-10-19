# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.cmttypes import SecurityStatus


def join_securitystatus_set(separator: str, securitystatuses: set[SecurityStatus]) -> str:
    """
    Given a set of violations, join it to a sorted string.

        Parameters:
            separator (str): The separator to use between items
            securitystatuses (set(SecurityStatus)): The set of security statuses
        Returns:
            (str): The string of joined securitystatuses
    """
    securitystatus_str = ""

    for securitystatus in sorted(securitystatuses):
        if securitystatus_str:
            securitystatus_str += separator
        securitystatus_str += repr(securitystatus)

    return securitystatus_str
