# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a ThemeStr return a string + its Curses attribute representation.
"""

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.curses_helper.themeattr_to_curses_merged import themeattr_to_curses_merged  # noqa: E501
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themestring_to_cursestuple(themestring: ThemeStr,
                               selected: bool | None = None) -> tuple[str, int]:
    """
    Given a themestring returns a cursestuple.

        Parameters:
            themestring (ThemeStr): The ThemeStr to convert
            selected (bool): [optional] True is selected, False otherwise
        Returns:
            (str, int): A curses tuple for use with addformattedarray()
    """
    string = str(themestring)
    themeattr = themestring.get_themeattr()

    if selected is None:
        selected = themestring.get_selected()
        if selected is None:
            selected = False

    return (string, themeattr_to_curses_merged(themeattr, selected))
