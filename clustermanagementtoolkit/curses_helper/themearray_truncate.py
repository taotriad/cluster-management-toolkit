# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Truncate a ThemeArray to the specified length.
"""

from clustermanagementtoolkit.curses_helper.themearray_flatten import themearray_flatten
from clustermanagementtoolkit.curses_helper.themearray_len import themearray_len
from clustermanagementtoolkit.curses_helper.themestr import ThemeArray
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themearray_truncate(themearray: list[ThemeRef | ThemeStr],
                        max_len: int) -> list[ThemeRef | ThemeStr]:
    """
    Given a themearray, truncate it to max_len.

        Parameters:
            themearray ([ThemeRef | ThemeStr]): A themearray
            max_len (int): The max length to truncate to
        Returns:
            ([ThemeRef | ThemeStr]): The truncated themearray
    """
    truncated_themearray: list[ThemeRef | ThemeStr] = []

    # For the time being (until we implement proper iteration
    # over ThemeArray elements) this is needed.
    if isinstance(themearray, ThemeArray):
        themearray = themearray.to_list()

    # To be able to truncate a themearray that can contain themerefs we need to flatten the array
    # (replace the themerefs with the corresponding themearray) first
    themearray_flattened = themearray_flatten(themearray)

    for element in themearray_flattened:
        max_element_len = max_len - themearray_len(truncated_themearray)
        if len(element) > max_element_len:
            string = str(element)
            attr = element.get_themeattr()
            selected = element.get_selected()
            truncated_themearray.append(ThemeStr(string[0:max_element_len],
                                                 attr, selected=selected))
            break
        truncated_themearray.append(element)

    return truncated_themearray
