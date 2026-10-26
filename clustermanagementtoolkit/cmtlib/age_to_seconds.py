# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a time in X1dX2hX3mX4sX5ms, convert it to seconds.
"""

import re


def age_to_seconds(age: str) -> int:
    """
    Given a time in X1dX2hX3mX4sX5ms, convert it to seconds.

        Parameters:
            age (str): A string in age format
        Returns:
            seconds (int): The number of seconds
        Raises:
            TypeError: The input was not a string
            ValueError: The input could not be parsed as an age string
    """
    seconds: int = 0
    match: bool = False

    if not isinstance(age, str):
        raise TypeError(f"age {age} is type {type(age)}, expected str")

    if not age:
        return -1

    # Split off milliseconds first, if any.
    if age.endswith("ms"):
        tmp = re.match(r"^(.*?)(\d+ms)", age)
        if tmp and tmp.span() != (0, 0):
            age = "" if tmp[1] is None else tmp[1]
            seconds += 0 if tmp[2] is None else round(int(tmp[2][:-2]) / 1000)
            match = True

    tmp = re.match(r"^(\d+d)?(\d+h)?(\d+m)?(\d+s)?", age)
    if tmp and tmp.span() != (0, 0):
        seconds += 0 if tmp[1] is None else int(tmp[1][:-1]) * 24 * 60 * 60
        seconds += 0 if tmp[2] is None else int(tmp[2][:-1]) * 60 * 60
        seconds += 0 if tmp[3] is None else int(tmp[3][:-1]) * 60
        seconds += 0 if tmp[4] is None else int(tmp[4][:-1])
        match = True

    if not match:
        raise ValueError(f"age regex did not match; age: {age}")

    return seconds
