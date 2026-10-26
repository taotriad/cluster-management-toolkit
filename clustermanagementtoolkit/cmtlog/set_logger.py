# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Register a logger.
"""

import logging
import logging.handlers

from clustermanagementtoolkit.cmtlog.logger import LogConfiguration
from clustermanagementtoolkit.cmtlog.logger import get_logger
from clustermanagementtoolkit.cmtlog.set_level import set_level

from clustermanagementtoolkit.cmtpaths import CMT_LOGS_DIR

from clustermanagementtoolkit.cmttypes import LogLevel


def set_logger(name: str, loglevel: LogLevel) -> None:
    """
    Registers a logger that generates log messages as YAML-list entries.

        Parameters:
            name (str): The name of the module that the logger is to be used in
            loglevel (LogLevel): Logging threshold
    """
    formatter = \
        logging.Formatter('- {'
                          '"timestamp": "%(timestamp)s", "severity": "%(levelname)s", '
                          '"facility": "%(name)s", "message": "%(message)s", '
                          '"file": "%(file)s", "function": "%(function)s", '
                          '"lineno": "%(linenr)s", "ppid": "%(process)s", %(messages)s'
                          '}')
    handler = \
        logging.handlers.RotatingFileHandler(CMT_LOGS_DIR.joinpath(f"{name}.log.yaml"),
                                             maxBytes=1_000_000, backupCount=10)
    handler.setFormatter(formatter)

    LogConfiguration.logger = logging.getLogger(name)
    logger = get_logger()
    logger.addHandler(handler)
    set_level(loglevel)
