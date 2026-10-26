# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Clear the list of tagged items.
"""

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration


def clear_tagged_items() -> None:
    """
    Clear the set of tagged items.
    """
    CursesConfiguration.tagged_items.clear()
