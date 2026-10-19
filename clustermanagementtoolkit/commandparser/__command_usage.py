# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Display usage information for a command.
"""

from clustermanagementtoolkit.commandparser.__usage import __usage
from clustermanagementtoolkit.commandparser.__sub_usage import __sub_usage


def __command_usage(options: list[tuple[str, str]], args: list[str]) -> int:
    """
    Display usage information for a single command.

        Parameters:
            options ([(str, str)]): [unused]
            args ([str]): The command to show help for
        Returns:
            (int): The return value from __usage()/__sub_usage()
    """
    if not args:
        return __usage(options, args)
    return __sub_usage(args[0])
