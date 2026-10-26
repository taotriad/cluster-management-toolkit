# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Split a version string into a tuple.
"""


def versiontuple(ver: str) -> tuple[str, ...]:
    """
    Split a version string into a tuple.

        Parameters:
            ver (str): The version string to split
        Returns:
            ((str, ...)): A variable-length tuple with one string per version component
        Raises:
            TypeError: The input was not a string
    """
    filled = []

    if not isinstance(ver, str):
        raise TypeError(f"ver is type {type(ver)}, expected str")

    for point in ver.split("."):
        filled.append(point.zfill(8))
    return tuple(filled)
