# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Wrapper used by textpads to modify the default behaviour for the Escape key.
"""

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration


def inputwrapper(keypress: int) -> int:
    """
    A wrapper used by textpads to change the input behaviour of the Escape key.

        Parameters:
            keypress (int): The keypress
        Returns:
            (int): The filtered keypress
    """
    if keypress == 27:  # ESCAPE
        CursesConfiguration.ignoreinput = True
        return 7
    return keypress
