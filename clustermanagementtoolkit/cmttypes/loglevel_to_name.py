# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a loglevel return its name.
"""

from typing import cast

from clustermanagementtoolkit.cmttypes.cmttypes_types import LogLevel
from clustermanagementtoolkit.cmttypes.cmttypes_types import loglevel_mappings


def loglevel_to_name(loglevel: LogLevel, default: str = "info") -> str:
    """
    Given a numerical loglevel, return its severity string.

        Parameters:
            loglevel (LogLevel): A numerical loglevel
            default (str): The default value to return if an invalid loglevel is passed
        Returns:
            (str): A severity string
    """
    if loglevel is None or loglevel != LogLevel.ALL \
            and (loglevel < LogLevel.EMERG or loglevel > LogLevel.DIFFSAME):
        return default.capitalize()
    return cast(str, loglevel_mappings.get(loglevel))
