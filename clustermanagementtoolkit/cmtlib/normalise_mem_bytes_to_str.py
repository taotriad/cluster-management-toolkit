# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given memory usage in bytes, convert it to a normalised string.
"""


def normalise_mem_bytes_to_str(mem_usage_bytes: int, fmt: str = "float") -> str:
    """
    Given memory usage in bytes, convert it to a normalised string.

        Parameters:
            mem_usage_bytes (int): The memory size in bytes
            fmt (str): Format as float or integer
        Returns:
            (str): The human readable mem usage with size suffix
        Raises:
            TypeError: size is not an integer
            ValueError: size is not >= 0
    """
    suffix = ""
    mem_usage: float = 0

    suffixes = (
        "",    # 1024 ** 1
        "Ki",  # 1024 ** 2
        "Mi",  # 1024 ** 3
        "Gi",  # 1024 ** 4
        "Ti",  # 1024 ** 5
        "Pi",  # 1024 ** 6
        "Ei",  # 1024 ** 7
        "Zi",  # 1024 ** 8
        "Yi",  # 1024 ** 9
    )

    if not isinstance(mem_usage_bytes, int):
        raise TypeError("mem_usage_bytes must be an int")

    mem_usage = float(mem_usage_bytes)

    if mem_usage < 0:
        raise ValueError("mem_usage_bytes must be >= 0")

    for i, suffix in enumerate(suffixes):
        if mem_usage < 1024 or i >= len(suffixes) - 1:
            break
        mem_usage /= 1024 ** 1

    if fmt == "int":
        return f"{int(mem_usage)}{suffix}B"
    return f"{mem_usage:0.1f}{suffix}B"
