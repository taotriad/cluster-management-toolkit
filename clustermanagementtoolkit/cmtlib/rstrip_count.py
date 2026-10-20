# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a string remove prefix and return the stripped string and the count of stripped characters.
"""


def rstrip_count(string: str, suffix: str) -> tuple[str, int]:
    """
    Given a string remove suffix
    and return the stripped string and the count of stripped characters.

        Parameters:
            string (str): The string to strip
            suffix (str): The suffix to strip
        Returns:
            ((str, int)): The stripped string and the count of stripped characters
    """
    stripped = string.rstrip(suffix)
    return stripped, len(string) - len(stripped)
