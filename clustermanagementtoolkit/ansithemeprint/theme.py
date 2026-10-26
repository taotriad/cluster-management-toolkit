# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helpers for references to the theme.
"""

from clustermanagementtoolkit.cmttypes import FilePath

theme_var: dict | None = None  # pylint: disable=invalid-name
themepath_var: FilePath | None = None  # pylint: disable=invalid-name


def get_theme() -> dict:
    """
    Return a reference to the theme.

        Returns:
            (dict): A reference to the theme.
    """
    if theme_var is None:
        return {}
    return theme_var


def get_themepath() -> FilePath | None:
    """
    Returns the path to the theme.

        Returns:
            (FilePath): Thepath to the theme.
    """
    return themepath_var


def set_theme(theme: dict | None = None) -> None:
    """
    Set the reference to the theme.

        Arguments:
            theme (dict): A reference to the theme.
    """
    global theme_var  # pylint: disable=global-statement
    theme_var = theme


def set_themepath(themepath: FilePath | None = None) -> None:
    """
    Set the path to the theme.

        Arguments:
            themepath (FilePath): The path to the theme.
    """
    global themepath_var  # pylint: disable=global-statement
    themepath_var = themepath
