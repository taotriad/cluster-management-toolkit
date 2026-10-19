# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from datetime import datetime
import re

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmtlib.none_timestamp import none_timestamp

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import LogLevel


# Will take a timestamp and convert it to datetime
def timestamp_to_datetime(timestamp: str) -> datetime:
    """
    Takes a timestamp and converts it to datetime.

        Parameters:
            timestamp (str): The timestamp string to convert
        Returns:
            (int | datetime): -1 if the timestamp was -1,
                              none_timestamp() if timestamp was None, 0, "", or "None",
                              datetime otherwise
    """
    default: datetime = none_timestamp()

    rtimestamp = timestamp

    if timestamp is None \
            or isinstance(timestamp, int) and timestamp == 0 \
            or isinstance(timestamp, str) and timestamp in ("", "None"):
        return default

    if timestamp == -1:
        return none_timestamp()

    # Just in case the timestamp isn't a string already
    timestamp = str(timestamp)

    # Timestamps that end with Z are already in UTC; strip that
    timestamp = timestamp.removesuffix("Z")

    # Timestamps that have both a numerical timezone offset and a timezone name do not make sense
    tmp = re.match(r"^(.+ [+-]\d{4}) [A-Z]{3}$", timestamp)
    if tmp is not None:
        timestamp = f"{tmp[1]}"

    # Some timestamps are weird
    tmp = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6})\d* ([+-]\d{4})$", timestamp)
    if tmp is not None:
        timestamp = f"{tmp[1]}{tmp[2]}"

    tmp = re.match(r"^(.+) ?([+-])(\d\d)(:|)(\d\d)$", timestamp)
    if tmp is not None:
        timestamp = f"{tmp[1]}{tmp[2]}{tmp[3]}{tmp[5]}"
    else:
        # If the timestamp has too many, or too few, decimals (should be 6), adjust it
        tmp = re.match(r"^(\d{4}-\d\d-\d\d.\d\d:\d\d:\d\d\.)(\d+)", timestamp)
        if tmp is not None and len(tmp[2]) != 6:
            timestamp = f"{tmp[1]}{tmp[2]:06.6}"
        # For timestamp without timezone add one; all timestamps are assumed to be UTC
        timestamp += "+0000"

    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%d %H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S%z"):
        try:
            return datetime.strptime(timestamp, fmt)  # noqa: DTZ007
        except ValueError:
            pass

    errmsg = [
        [("Could not parse timestamp: ", "default"),
         (f"{rtimestamp}", "argument"),
         ("; defaulting to ", "default"),
         (f"{none_timestamp()}", "argument"),
         (".", "default")],
    ]

    unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
    cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)

    return none_timestamp()
