# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Configuration data for the curses UI.
"""

from typing import ClassVar

from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


# pylint: disable-next=too-few-public-methods
class CursesConfiguration:
    """
    Configuration options for the curses UI.
    """
    abouttext: ClassVar[list[list[ThemeRef | ThemeStr]]] = []
    borders: ClassVar[bool] = True
    ignoreinput: ClassVar[bool] = False
    mousescroll_enable: ClassVar[bool] = False
    mousescroll_up: ClassVar[int] = 0b10000000000000000
    mousescroll_down: ClassVar[int] = 0b1000000000000000000000000000
    mousemask: ClassVar[int] = 0
    tagged_items: ClassVar[set] = set()
