# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Align a string in the specified orientation (left/right) and pad it to length.
"""

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_len


def align_and_pad(array: list[ThemeRef | ThemeStr], fieldlen: int,
                  pad: bool = False, ralign: bool = False,
                  selected: bool = False) -> list[ThemeRef | ThemeStr]:
    """
    Given a field, align to the left or right, and pad it to fieldlen.

        Parameters:
            array (ThemeArray): The themearray to align and pad
            fieldlen (int): The length of the field
            pad (bool): Pad the string?
            ralign (bool): Align the data to the right?
            selected (bool): Mark the field as selected?
        Returns:
            (ThemeArray): The formatted list
    """
    tmp_array: list[ThemeRef | ThemeStr] = []
    stringlen = themearray_len(array)

    # If the string is exactly the size of the field we don't need to realign.
    if fieldlen != stringlen:
        if ralign:
            tmp_array.append(ThemeStr("".ljust(fieldlen - stringlen),
                                      ThemeAttr("types", "generic"), selected))
            tmp_array += array
        else:
            tmp_array += array
            tmp_array.append(ThemeStr("".ljust(fieldlen - stringlen),
                                      ThemeAttr("types", "generic"), selected))
    else:
        tmp_array = array
    if pad:
        tmp_array.append(ThemeRef("separators", "pad", selected))
    return tmp_array
