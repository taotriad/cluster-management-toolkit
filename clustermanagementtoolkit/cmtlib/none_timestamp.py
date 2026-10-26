# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the timestamp used to represent None.
"""

from datetime import datetime, timedelta, UTC, date


def none_timestamp() -> datetime:
    """
    Return the timestamp used to represent None.

        Returns:
            timestamp (datetime): A "None" timestamp
    """
    return (datetime.combine(date.min, datetime.min.time())
            + timedelta(days=1)).replace(tzinfo=UTC)
