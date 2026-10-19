# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def replace_quotes(string: str, policy: str = "keep") -> str:
    """
    Convert and/or substitute quotes.

        Parameters:
            string (str): The string to process
            policy (str): The policy to use
        Returns:
            (str): The processed string
    """
    if policy == "pretty":
        string = string.replace("\\\"", "“")
    elif policy == "same":
        string = string.replace("\\\"", "\"")
    elif policy == "stripsurrounding" and string.startswith("\"") and string.endswith("\""):
        string = string[1:-1]

    return string
