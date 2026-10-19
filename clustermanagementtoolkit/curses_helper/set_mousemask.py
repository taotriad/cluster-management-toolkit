# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Enable/disable mouse support.
"""

import curses

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration


def set_mousemask(mask: int) -> None:
    """
    Enable/disable mouse support.

        Parameters:
            mask (int): The mouse mask to set
    """
    curses.mousemask(mask)
    CursesConfiguration.mousemask = mask
