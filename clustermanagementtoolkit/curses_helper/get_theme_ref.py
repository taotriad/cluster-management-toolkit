# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a reference to the theme.
"""

from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


def get_theme_ref() -> dict:
    """
    Get a reference to the theme.

        Returns:
            (str): A reference to the theme
    """
    return ThemeStrConfiguration.theme
