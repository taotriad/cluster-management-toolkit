# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert newlines and optionally strip or replace them.
"""


def replace_newlines(string: str, policy: str = "keep") -> str:
    """
    Convert newlines, and optionally strip or replace them.

        Parameters:
            string (str): The string to process
            policy (str): The policy to use
        Returns:
            (str): The processed string
    """
    string = string.replace("\r\n", "\n")
    if policy == "strip":
        string = string.replace("\n", "").rstrip()
    elif policy == "replace":
        string = string.replace("\n", " ").rstrip()
    elif policy == "escape":
        string = string.replace("\n", "\\n").rstrip()

    return string
