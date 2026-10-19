# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Left-align a formatted string with padding.
"""

from clustermanagementtoolkit.ansithemeprint.ansithemestr import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint.themearray_len import themearray_len


def themearray_ljust(themearray: list[ANSIThemeStr], width: int) -> list[ANSIThemeStr]:
    """
    Return a ljust:ed themearray (will always pad with ANSIThemeStr("", "default")).

        Parameters:
            themearray ([ANSIThemeStr]): The themearray to ljust
        Return:
            The ljust:ed themearray
    """
    tlen = themearray_len(themearray)
    if tlen < width:
        themearray = themearray + [ANSIThemeStr("".ljust(width - tlen), "default")]
    return themearray
