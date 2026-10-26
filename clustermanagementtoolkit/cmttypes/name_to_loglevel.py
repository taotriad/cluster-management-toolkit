# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a loglevel name, return its loglevel.
"""

from clustermanagementtoolkit.cmttypes.cmttypes_types import LogLevel
from clustermanagementtoolkit.cmttypes.cmttypes_types import loglevel_mappings


def name_to_loglevel(severity: str, default: LogLevel = LogLevel.DEFAULT) -> LogLevel:
    """
    Given a severity string, return its numerical number.

        Parameters:
            severity (str): A severity string
            default (LogLevel): Default loglevel to return if an invalid value is passed
        Returns:
            (LogLevel): The corresponding numerical loglevel
    """
    for severity_, severity_string_ in loglevel_mappings.items():
        if severity_string_.lower() == severity.lower():
            return severity_

    return default
