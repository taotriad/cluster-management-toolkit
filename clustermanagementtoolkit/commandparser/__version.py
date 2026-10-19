# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Display version information.
"""

from clustermanagementtoolkit import about

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.commandparser import commandparser_types
from clustermanagementtoolkit.ansithemeprint import ansithemeprint


# pylint: disable-next=unused-argument
def __version(options: list[tuple[str, str]], args: list[str]) -> int:
    """
    Display version information.

        Parameters:
            options ([(str, str)]): [unused]
            args ([str]): [unused]
        Returns:
            (int): 0
    """
    ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname} ", "programname"),
                    ANSIThemeStr(f"{commandparser_types.programversion}", "version")])
    ansithemeprint([ANSIThemeStr(f"{about.PROGRAM_SUITE_FULL_NAME} "
                                 f"({about.PROGRAM_SUITE_NAME}) ", "programname"),
                    ANSIThemeStr(f"{about.PROGRAM_SUITE_VERSION}", "version")])
    print()
    print(about.COPYRIGHT)
    print(about.LICENSE)
    print()
    print(commandparser_types.programauthors)
    return 0
