# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def normalise_cpu_usage_to_millicores(cpu_usage: str) -> float:
    """
    Given CPU usage information, convert it to CPU usage in millicores.

        Parameters:
            cpu_usage(union(int, str)): The CPU usage
        Returns:
            (float): CPU usage in millicores
    """
    cpu_usage_millicores: float = 0

    if not isinstance(cpu_usage, str):
        raise TypeError("cpu_usage must be a str")

    if cpu_usage.isnumeric():
        cpu_usage_millicores = int(cpu_usage) * 1000 ** 1
    elif cpu_usage.endswith("k"):
        cpu_usage_millicores = int(cpu_usage[0:-1]) * 1000 ** 1
    elif cpu_usage.endswith("m"):
        cpu_usage_millicores = int(cpu_usage[0:-1])
    elif cpu_usage.endswith("u"):
        cpu_usage_millicores = int(cpu_usage[0:-1]) / 1000 ** 1
    elif cpu_usage.endswith("n"):
        cpu_usage_millicores = int(cpu_usage[0:-1]) / 1000 ** 2
    else:
        raise ValueError(f"Unknown unit for CPU usage in {cpu_usage}")
    return cpu_usage_millicores
