# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def normalise_mem_to_bytes(mem_usage: str) -> int:
    """
    Given a memory usage string, normalise it to bytes.

        Parameters:
            mem_usage (str): The amount of memory used
        Returns:
            (int): The amount of memory used in bytes
    """
    mem = 0

    unit_lookup = {
        "Ki": 1024 ** 1,
        "Mi": 1024 ** 2,
        "Gi": 1024 ** 3,
        "Ti": 1024 ** 4,
        "Pi": 1024 ** 5,
        "Ei": 1024 ** 6,
        "Zi": 1024 ** 7,
        "Yi": 1024 ** 8,
    }

    if not isinstance(mem_usage, (int, str)):
        raise TypeError("mem_usage must be an integer-string (optionally with a valid unit) or int")

    if isinstance(mem_usage, int) or isinstance(mem_usage, str) and mem_usage.isnumeric():
        mem = int(mem_usage)
    else:
        for key, value in unit_lookup.items():
            if mem_usage.endswith(key):
                mem = int(mem_usage[0:-len(key)]) * value
                break
        else:
            raise ValueError(f"Unknown unit for memory usage in {mem_usage}")

    return mem
