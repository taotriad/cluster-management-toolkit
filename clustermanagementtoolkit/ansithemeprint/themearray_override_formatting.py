# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Override the formatting of a formatted string.
"""

import copy

from clustermanagementtoolkit.ansithemeprint.ansithemestr import ANSIThemeStr


def themearray_override_formatting(themearray: list[ANSIThemeStr],
                                   formatting: str | None) -> list[ANSIThemeStr]:
    """
    Override the formatting of an ANSIThemeArray (list[ANSIThemeStr]).

        Parameters:
            themearray ([ANSIThemeStr]): The themearray to reformat
            formatting (str): The new formatting to apply
        Return:
            ([ANSIThemeStr]): The reformatted ANSIThemeArray
    """
    new_themearray = []

    for themestr in themearray:
        new_themestr = copy.deepcopy(themestr)
        if formatting is not None:
            themestr = new_themestr.format(formatting)
        new_themearray.append(new_themestr)

    return new_themearray
