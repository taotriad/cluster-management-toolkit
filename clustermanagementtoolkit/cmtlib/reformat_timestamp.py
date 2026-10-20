# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Reformat timestamps as ISO-8601.
"""

from datetime import datetime


def reformat_timestamp(timestamp: str) -> str:
    """
    Takes a timestamp in various formats and formats it the proper(tm) way; ISO-8601.

        Parameters:
            timestamp (str): A timestamp str
        Returns:
            (str): A timestamp str in YYYY-MM-DD HH:MM:SS format
    """
    if timestamp is not None:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f%z",
                    "%Y-%m-%d %H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%f%z",
                    "%Y-%m-%dT%H:%M:%S%z"):

            try:
                return f"{datetime.strptime(timestamp, fmt).astimezone():%Y-%m-%d %H:%M:%S}"
            except ValueError:
                pass

    raise ValueError(f"Could not parse timestamp: {timestamp} (type: {type(timestamp)})")
