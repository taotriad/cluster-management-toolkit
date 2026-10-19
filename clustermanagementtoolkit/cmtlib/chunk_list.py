# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from collections.abc import Generator
from typing import Any


def chunk_list(items: list[Any], chunksize: int) -> Generator[list, None, None]:
    """
    Split a list into sublists, each up to chunksize elements long.

        Parameters:
            items ([Any]): The list to split
            chunksize (int): The chunksize
        Returns:
            ([Any]): A generator for the chunked list
        Raises:
            TypeError: items is not a list or chunksize is not an integer
            ValueError: chunksize is < 1
    """
    if not isinstance(items, list):
        raise TypeError("items must be a list")
    if not isinstance(chunksize, int):
        raise TypeError("chunksize must by an integer > 0")
    if chunksize < 1:
        raise ValueError(f"Invalid chunksize {chunksize}; chunksize must be > 0")
    for i in range(0, len(items), chunksize):
        yield items[i:i + chunksize]
