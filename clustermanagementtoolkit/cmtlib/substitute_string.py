# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def substitute_string(string: str, substitutions: dict) -> str:
    """
    Substitutes substrings in a string.

        Parameters:
            string (str): The string to perform substitutions on
            substitutions (dict): A dict where key is the substring to match against,
                                  and value is the replacement for that substring
        Returns:
            (str): The string with substitutions performed
    """
    for key, value in substitutions.items():
        if string is None or value is None:
            continue
        string = string.replace(key, value)
    return string
