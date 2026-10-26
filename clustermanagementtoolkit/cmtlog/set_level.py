# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Set loglevel.
"""

import logging

from clustermanagementtoolkit.cmtlog.logger import get_logger

from clustermanagementtoolkit.cmttypes import LogLevel


def set_level(loglevel: LogLevel) -> None:
    """
    Set logging threshold.

        Parameters:
            loglevel (LogLevel): One of LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARNING,
                                 LogLevel.ERR, LogLevel.CRIT
        Raises:
            TypeError: logger called without being initialized
    """
    logger = get_logger()
    if logger is None:
        raise TypeError(f"cmtlog.{__name__}() called without being initialized; aborting.")

    if loglevel == LogLevel.DEBUG:
        logger.setLevel(logging.DEBUG)
    elif loglevel == LogLevel.INFO:
        logger.setLevel(logging.INFO)
    elif loglevel == LogLevel.WARNING:
        logger.setLevel(logging.WARNING)
    elif loglevel == LogLevel.ERR:
        logger.setLevel(logging.ERROR)
    elif loglevel == LogLevel.CRIT:
        logger.setLevel(logging.CRITICAL)
    else:
        raise ValueError(f"cmtlog.{__name__}() called with invalid loglevel {loglevel}")
