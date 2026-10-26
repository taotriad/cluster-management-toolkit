# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Structured log module for CMT.
"""

from clustermanagementtoolkit.cmtlog.log import log
from clustermanagementtoolkit.cmtlog.logger import get_logger
from clustermanagementtoolkit.cmtlog.log_array_to_string import log_array_to_string
from clustermanagementtoolkit.cmtlog.set_level import set_level
from clustermanagementtoolkit.cmtlog.set_logger import set_logger

__all__ = [
    "get_logger",
    "log",
    "log_array_to_string",
    "set_level",
    "set_logger",
]
