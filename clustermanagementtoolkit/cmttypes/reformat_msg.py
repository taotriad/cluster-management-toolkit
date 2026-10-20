# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Reformat a structured error message to plaintext.
"""


def reformat_msg(msg: list[list[tuple[str, str]]]) -> str:
    """
    Given a structured error message return a plaintext representation.

        Parameters:
            msg ([[(str, str)]]): A structured message for format
        Returns:
            (str): The plaintext representation
    """
    joined_strings = []

    for line in msg:
        joined_string = ""
        for string, _fmt in line:
            joined_string += string
        joined_strings.append(joined_string)
    return "\n".join(joined_strings)
