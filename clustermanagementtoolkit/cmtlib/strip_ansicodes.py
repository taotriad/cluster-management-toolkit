# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Strip all ANSI-formatting from a string.
"""

import re


def strip_ansicodes(message: str) -> str:
    """
    Strip all ANSI-formatting from a string.

        Parameters:
            message (str): The string to strip
        Returns:
            (str): The stripped string
        Raises:
            TypeError: The input was not a string
    """
    if not isinstance(message, str):
        raise TypeError(f"message is type {type(message)}, expected str")

    message = message.replace("\\x1b", "\x1b").replace("\\u001b", "\x1b")
    tmp = re.findall(r"("
                     r"\x1b\[\d+m|"
                     r"\x1b\[\d+;\d+m|"
                     r"\x1b\[\d+;\d+;\d+m|"
                     r".*?)", message)
    return "".join(item for item in tmp if not item.startswith("\x1b"))
