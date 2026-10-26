# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the list of loglevel names.
"""

from clustermanagementtoolkit.cmttypes.cmttypes_types import loglevel_mappings


def get_loglevel_names() -> list[str]:
    """
    Ugly way of removing duplicate values from dict.

        Returns:
            ([str]): The unique severities
    """
    return list(dict.fromkeys(list(loglevel_mappings.values())))
