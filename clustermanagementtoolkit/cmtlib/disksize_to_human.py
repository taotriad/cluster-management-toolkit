# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a disksize in bytes, convert it to a more readable format with size suffix.
"""

from clustermanagementtoolkit.cmtlib.normalise_mem_bytes_to_str import normalise_mem_bytes_to_str


def disksize_to_human(size: int) -> str:
    """
    Given a disksize in bytes, convert it to a more readable format with size suffix.

        Parameters:
            size (int): The disksize in bytes
        Returns:
            (str): The human readable disksize with size suffix
        Raises:
            TypeError: size is not an integer
            ValueError: size is not >= 0
    """
    # If we cannot convert the value, just return the input value.
    try:
        size = int(size)
    except ValueError:
        return str(size)

    tmp = normalise_mem_bytes_to_str(size, fmt="int")
    if tmp[:-1].isnumeric():
        tmp = f"{tmp[:-1]} bytes"
    return tmp
