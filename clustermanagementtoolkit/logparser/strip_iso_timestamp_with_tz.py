# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Strip timestamps that include a timezone and return the message.
"""

import re


# 2020-02-20 13:47:01.531 GMT
def strip_iso_timestamp_with_tz(message: str) -> str:
    """
    Given a string with a timestamp and timezone, return that string without the timestamp.

        Parameters:
            message (str): The message to strip
        Returns:
            (str): The stripped message
    """
    re_tmp = re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d [A-Z]{3}(\s+?|$)(.*)", message)
    if re_tmp is not None:
        message = re_tmp[2]
    return message
