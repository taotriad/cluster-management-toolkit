# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the default mouse mask.
"""

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration


def get_mousemask() -> int:
    """
    Get the default mouse mask.

        Returns:
            (int): The mouse mask
    """
    return CursesConfiguration.mousemask
