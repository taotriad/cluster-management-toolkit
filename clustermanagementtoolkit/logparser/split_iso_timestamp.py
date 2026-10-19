# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from datetime import datetime
import re

from clustermanagementtoolkit.cmtlib import none_timestamp


# pylint: disable-next=too-many-statements
def split_iso_timestamp(message: str, timestamp: datetime) -> tuple[datetime, str]:
    """
    Split a message into timestamp and remaining message.

        Parameters:
            message (str): The message to strip the timestamp from
            timestamp (datetime): The datetime to return if the message doesn't have a timestamp
        Returns:
            (datetime, str): Return the remainder of the message and the datetime
    """
    old_timestamp = timestamp
    tmp_timestamp = ""

    # This while loop is merely to allow for breaking out anywhere
    while True:
        # 2020-02-07T13:12:24[.,]224Z (Z = UTC)
        re_tmp = re.match(r"^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d[.,]\d+)Z ?(.*)", message)
        if re_tmp is not None:
            ymd = re_tmp[1]
            hmsms = re_tmp[2][0:len("HH:MM:SS.sss")].replace(",", ".")
            tmp_timestamp = f"{ymd} {hmsms}+0000"
            message = re_tmp[3]
            break

        # 2020-02-13T12:06:18[.,]011345 [+-]00:00 (+timezone)
        # 2020-09-23T17:12:32[.,]183967091[+-]03:00
        # 2024-11-02 23:20:35[.,]121725861 +0000
        re_tmp = re.match(r"^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d[.,]\d+) "
                          r"?([\+-])(\d\d):?(\d\d) ?(.*)",
                          message)
        if re_tmp is not None:
            ymd = re_tmp[1]
            hmsms = re_tmp[2][0:len("HH:MM:SS.sss")].replace(",", ".")
            tzsign = re_tmp[3]
            tzhour = re_tmp[4]
            tzmin = re_tmp[5]
            tmp_timestamp = f"{ymd} {hmsms}{tzsign}{tzhour}{tzmin}"
            message = re_tmp[6]
            break

        # 2020-02-13 12:06:18[+-]00:00 (+timezone)
        # [2020-02-13 12:06:18 [+-]00:00] (+timezone)
        # 2020-02-13T12:06:18[+-]0000 (+timezone)
        re_tmp = re.match(r"^\[?(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d) "
                          r"?([\+-])(\d\d):?(\d\d)\]? ?(.*)",
                          message)
        if re_tmp is not None:
            ymd = re_tmp[1]
            hms = re_tmp[2]
            tzsign = re_tmp[3]
            tzhour = re_tmp[4]
            tzmin = re_tmp[5]
            tmp_timestamp = f"{ymd} {hms}.000{tzsign}{tzhour}{tzmin}"
            message = re_tmp[6]
            break

        # 2020-02-20 13:47:41[.,]008416 (assume UTC)
        # 2020-02-20 13:47:41[.,]008416: (assume UTC)
        # 2020/02/20 13:47:41[.,]008416 (assume UTC)
        # 2020-02-20 13:47:41[.,]008416Z (Z = UTC)
        # 2020.02.20 13:47:41[.,]008416 (assume UTC)
        re_tmp = re.match(r"^(\d{4})[-/.](\d\d)[-/.](\d\d) (\d\d:\d\d:\d\d[.,]\d+)[Z:]? ?(.*)",
                          message)
        if re_tmp is not None:
            year = re_tmp[1]
            month = re_tmp[2]
            day = re_tmp[3]
            hmsms = re_tmp[4][0:len("HH:MM:SS.sss")].replace(",", ".")
            tmp_timestamp = f"{year}-{month}-{day} {hmsms}+0000"
            message = re_tmp[5]
            break

        # [2021-12-18T20:15:36Z]
        # 2021-12-18T20:15:36Z
        re_tmp = re.match(r"^\[?(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)Z\]? ?(.*)", message)
        if re_tmp is not None:
            ymd = re_tmp[1]
            hms = re_tmp[2]
            tmp_timestamp = f"{ymd} {hms}.000+0000"
            message = re_tmp[3]
            break

        # 2020-02-20 13:47:41 (assume UTC)
        # 2020/02/20 13:47:41 (assume UTC)
        re_tmp = re.match(r"^(\d{4})[-/](\d\d)[-/](\d\d) (\d\d:\d\d:\d\d) ?(.*)", message)
        if re_tmp is not None:
            year = re_tmp[1]
            month = re_tmp[2]
            day = re_tmp[3]
            hms = re_tmp[4]
            tmp_timestamp = f"{year}-{month}-{day} {hms}.000+0000"
            message = re_tmp[5]
            break

        # 2020-02-07 13:12:24[.,]224
        # [2020-02-07 13:12:24[.,]224]
        re_tmp = re.match(r"^\[?(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(,|\.)(\d+)\]? ?(.*)", message)
        if re_tmp is not None:
            ymd = re_tmp[1]
            hms = re_tmp[2]
            # This just matches the separator; we don't use it
            # _sep = re_tmp[3]
            ms = re_tmp[4]
            tmp_timestamp = f"{ymd} {hms}.{ms}+0000"
            message = re_tmp[5]
            break

        break

    if old_timestamp == none_timestamp() and tmp_timestamp:
        timestamp = datetime.strptime(tmp_timestamp, "%Y-%m-%d %H:%M:%S.%f%z")

    # message + (timestamp|none_timestamp()) is passed in,
    # so it is safe just to return it too.
    return timestamp, message
