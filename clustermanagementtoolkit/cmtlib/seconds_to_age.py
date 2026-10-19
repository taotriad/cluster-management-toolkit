# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

# pylint: disable-next=too-many-branches
def seconds_to_age(seconds: int, negative_is_skew: bool = False) -> str:
    """
    Given a time in seconds, convert it to X1dX2hX3mX4s.

        Parameters:
            seconds (int): The number of seconds
            negative_is_skew (bool): Should a negative timestamp
                                     return a clock skew warning (default: -age)
        Returns:
            (str): The age string
        Raises:
            TypeError: The input was not an integer
    """
    if isinstance(seconds, str):
        if seconds == "":
            return ""
        try:
            seconds = int(seconds)
        except ValueError:
            pass

    if not isinstance(seconds, int):
        raise TypeError(f"age {seconds} is type {type(seconds)}, expected int")

    age = ""
    fields = 0

    if seconds < -1:
        sign = "-"
    else:
        sign = ""

    if seconds < -1 and negative_is_skew:
        return "<clock skew detected>"

    seconds = abs(seconds)

    if seconds == 0:
        return "<unset>"
    if seconds >= 24 * 60 * 60:
        days = seconds // (24 * 60 * 60)
        seconds -= days * 24 * 60 * 60
        age += f"{days}d"
        if days >= 7:
            return f"{sign}{age}"
        fields += 1
    if seconds >= 60 * 60:
        hours = seconds // (60 * 60)
        seconds -= hours * 60 * 60
        age += f"{hours}h"
        if hours >= 12:
            return f"{sign}{age}"
        fields += 1
    if seconds >= 60 and fields < 2:
        minutes = seconds // 60
        seconds -= minutes * 60
        age += f"{minutes}m"
        fields += 1
    if seconds > 0 and fields < 2:
        age += f"{seconds}s"

    return f"{sign}{age}"
