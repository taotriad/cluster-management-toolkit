# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper that processes timestamps.
"""

from collections.abc import Sequence
from datetime import datetime
from typing import Any, cast

from clustermanagementtoolkit.cmtlib import get_since
from clustermanagementtoolkit.cmtlib import none_timestamp
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime


def __process_timestamp(value: Sequence[int | str] | str,
                        action: str, formatter: str) -> datetime | int:
    new_value: Any = None

    if action in ("earliest", "latest") and isinstance(value, (list, tuple)):
        tmp_timestamp: datetime = none_timestamp()
        for tmp1 in value:
            if tmp1 is None or tmp1 == -1:
                continue
            # The only valid integer value is -1
            timestamp = timestamp_to_datetime(cast(str, tmp1))
            if tmp_timestamp == none_timestamp():
                tmp_timestamp = timestamp
            else:
                if timestamp < tmp_timestamp and action == "earliest" \
                        or timestamp > tmp_timestamp and action == "latest":
                    tmp_timestamp = timestamp
        new_value = tmp_timestamp
    else:
        if value == -1:
            new_value = none_timestamp()
        elif isinstance(value, str) and value.startswith("<") and value.endswith(">"):
            # Hmmm, what's this used by?
            new_value = value
        else:
            new_value = timestamp_to_datetime(cast(str, value))

    if formatter == "age":
        # If we are gonna format this as age we want this passed through get_since()
        return get_since(new_value)

    return new_value
