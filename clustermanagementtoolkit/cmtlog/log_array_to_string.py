# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert a list of strings to text that can be written to a YAML-file.
"""

from typing import cast

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr


def log_array_to_string(msglist: list[str | list[ANSIThemeStr]]) -> str:
    """
    Convert a list of strings or a list of ANSIThemeArray to a text representation
    that can be written to a YAML-file.

        Parameters:
            msglist ([str|[ANSITHemeStr]): The list of messages
        Returns:
            (str): A string representation of the list of messages
    """
    if not msglist:
        return ""

    if isinstance(msglist[0], str):
        return f'"strarray": [{", ".join(cast(list[str], msglist))}]'

    loglines = []
    for line in msglist:
        logline = []
        for linesegment in line:
            linesegment = cast(ANSIThemeStr, linesegment)
            logline.append(f'{{"string": "{linesegment!s}", '
                           f'"themeref": "{linesegment.themeref}"}}')
        loglines.append(f'[{", ".join(logline)}]')
    return f'"themearray": [{", ".join(loglines)}]'
