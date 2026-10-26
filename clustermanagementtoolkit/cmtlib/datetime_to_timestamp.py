# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a timestamp in datetime format, convert it to a string.
"""

from datetime import date, datetime

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmtlib.none_timestamp import none_timestamp

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# Will take datetime and convert it to a timestamp
def datetime_to_timestamp(timestamp: datetime) -> str:
    """
    Given a timestamp in datetime format, convert it to a string.

        Parameters:
            timestamp (datetime): The timestamp in datetime
        Returns:
            (str): The timestamp in string format
    """
    if not (timestamp is None or isinstance(timestamp, (date, datetime))):
        msg = [
            [("datetime_to_timestamp()", "emphasis"),
             (" initialised with invalid argument(s):", "error")],
            [("timestamp = ", "default"),
             (f"{timestamp}", "argument"),
             (" (type: ", "default"),
             (f"{type(timestamp)}", "argument"),
             (", expected: ", "default"),
             (f"{datetime}", "argument"),
             (")", "default")],
        ]

        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(msg)

        raise ProgrammingError(unformatted_msg,
                               severity=LogLevel.ERR,
                               formatted_msg=formatted_msg)

    if timestamp is None or timestamp == none_timestamp():
        string = ""
    elif timestamp == datetime.fromtimestamp(0).astimezone():
        # Replace epoch with an empty string
        # with the same length as a timestamp
        string = "".ljust(len(str(datetime.fromtimestamp(0).astimezone())))
    elif isinstance(timestamp, datetime):
        string = f"{timestamp.astimezone():%Y-%m-%d %H:%M:%S}"
    else:
        string = f"{timestamp:%Y-%m-%d}"
    return string
