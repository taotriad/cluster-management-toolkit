# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from datetime import datetime, UTC

from clustermanagementtoolkit.cmtlib.none_timestamp import none_timestamp


def get_since(timestamp: int | datetime | None) -> int:
    """
    Given either a datetime, or an integer, returns how old that
    timestamp is in seconds.

        Parameters:
            timestamp ([int | datetime]): A time in the past
        Returns:
            (int): The number of seconds, 0 if timestamp is None,
                   or -1 if the none_timestamp() was provided
    """
    if timestamp is None:
        return 0

    if not isinstance(timestamp, (int, datetime)):
        raise TypeError(f"timestamp is type {type(timestamp)}, expected int or datetime")

    if timestamp == -1 or timestamp == none_timestamp():
        since = -1
    # If the timestamp is an integer we assume it to already be in seconds
    elif isinstance(timestamp, int):
        since = timestamp
    else:
        timediff = datetime.now(UTC) - timestamp
        since = timediff.days * 24 * 60 * 60 + timediff.seconds

    return since
