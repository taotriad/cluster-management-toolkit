# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Clamp value inside the range minval, maxval.
"""


def clamp(value: float, minval: float, maxval: float) -> int | float:
    """
    Clamp value inside the range minval, maxval.

        Parameters:
            value (int | float): The value to clamp
            minval (int | float): The minimum allowed value
            maxval (int | float): The maximum allowed value
        Returns:
            (int | float): The clamped value
    """
    if not isinstance(value, (int, float)):
        raise TypeError("value must be an integer or float")
    if not isinstance(minval, (int, float)) or not isinstance(maxval, (int, float)):
        raise TypeError("maxval and minval must be integers or floats")
    if minval > maxval:
        raise ValueError(f"maxval ({maxval}) must be >= minval ({minval})")
    return min(maxval, max(minval, value))
