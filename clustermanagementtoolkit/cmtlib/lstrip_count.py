# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def lstrip_count(string: str, prefix: str) -> tuple[str, int]:
    """
    Given a string remove prefix
    and return the stripped string and the count of stripped characters.

        Parameters:
            string (str): The string to strip
            prefix (str): The prefix to strip
        Returns:
            ((str, int)): The stripped string and the count of stripped characters
    """
    stripped = string.lstrip(prefix)
    return stripped, len(string) - len(stripped)
