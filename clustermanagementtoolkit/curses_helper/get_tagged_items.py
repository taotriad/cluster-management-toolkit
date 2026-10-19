# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the set of all tagged items.
"""

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration


def get_tagged_items() -> set:
    """
    Return a set with the UID of all tagged items.

        Returns:
            (set): A set of UIDs
    """
    return CursesConfiguration.tagged_items
