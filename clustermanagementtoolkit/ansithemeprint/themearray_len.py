# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the length of a themed string.
"""

from clustermanagementtoolkit.ansithemeprint.ansithemestr import ANSIThemeStr


def themearray_len(themearray: list[ANSIThemeStr]) -> int:
    """
    Return the length of a themearray.

        Parameters:
            themearray ([ANSIThemeStr]): The themearray to return the length of
        Return:
            The length of the themearray
    """
    return sum(map(len, themearray))
