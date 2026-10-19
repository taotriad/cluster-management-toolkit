# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Configuration used by CMTLog.
"""

import logging
from typing import cast, ClassVar


# pylint: disable-next=too-few-public-methods
class LogConfiguration:
    """
    Configuration for CMTLog.
    """
    logger: ClassVar[logging.Logger | None] = None


def get_logger() -> logging.Logger:
    """
    Return a reference to the logger.

        Returns:
            (logging.Logger): A reference to the logger
    """
    return cast(logging.Logger, LogConfiguration.logger)
