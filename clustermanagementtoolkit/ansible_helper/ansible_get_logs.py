# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Returns a list of all available logs.
"""

from datetime import datetime
from pathlib import Path
import re

from clustermanagementtoolkit.cmtpaths import ANSIBLE_LOGS_DIR

from clustermanagementtoolkit.cmttypes import FilePath


def ansible_get_logs() -> list[tuple[str, str, FilePath, datetime]]:
    """
    Returns a list of all available logs.

        Returns:
            (str, str, FilePath, datetime):
                (str): Full name
                (str): Name
                (FilePath): The path to the log file
                (datetime): The timestamp
    """
    logs = []

    timestamp_regex = re.compile(r"^(\d{4}-\d\d-\d\d_\d\d:\d\d:\d\d\.\d+[+-]\d\d:\d\d)_(.*)")

    for path in Path(ANSIBLE_LOGS_DIR).iterdir():
        filename = str(path.name)
        if (re_tmp := timestamp_regex.match(filename)) is None:
            # Skip files that cannot be interpreted as filenames.
            continue
        date = datetime.strptime(re_tmp[1], "%Y-%m-%d_%H:%M:%S.%f%z")
        name = re_tmp[2]
        logs.append((filename, name, FilePath(path), date))
    return logs
