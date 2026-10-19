# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Log a message.
"""

from collections.abc import Callable
from datetime import datetime, UTC
import inspect
import os
from typing import Any

from clustermanagementtoolkit.cmtlog.log_array_to_string import log_array_to_string
from clustermanagementtoolkit.cmtlog.logger import get_logger

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get


def __loglevel_to_logger(loglevel: LogLevel) -> Callable:
    """
    Return a logger for the specified loglevel.

        Parameters:
            loglevel (LogLevel): The loglevel to return a logger for
        Returns:
            (Callable): A logger callable
        Raises:
            ValueError: Unsupported LogLevel
            TypeError: logger called without being initialized
    """
    logger = get_logger()
    if logger is None:  # pragma: no cover
        raise TypeError("cmtlog.__loglevel_to_logger() "
                        "called without being initialized; aborting.")

    if loglevel == LogLevel.DEBUG:
        return logger.debug
    if loglevel == LogLevel.INFO:
        return logger.info
    if loglevel == LogLevel.WARNING:
        return logger.warning
    if loglevel == LogLevel.ERR:
        return logger.error
    if loglevel == LogLevel.CRIT:
        return logger.critical
    raise ValueError(f"Unsupported LogLevel: {loglevel!r}; "
                     "supported LogLevels: {DEBUG|INFO|WARNING|ERR|CRIT}.")


def log(loglevel: LogLevel, **kwargs: Any) -> None:
    """
    Log a message.

        Parameters:
            loglevel (LogLevel): The level to log at
            **kwargs (dict[str, Any]): Keyword arguments
                msg (str): An unformatted log message
                messages ([str|[ANSIThemeStr]]): A list of unformatted strings or formatted strings
    """
    logger = get_logger()

    msg = deep_get(kwargs, DictPath("msg"), "")
    messages = deep_get(kwargs, DictPath("messages"), [])

    if logger is None:
        # If an exception occurs before the logger has been initialised we do not want
        # the program to abort without a chance to raise an exception, so just return here.
        return

    if not messages and not msg:
        messages = ["Attempted to log without log message"]

    if not messages:
        messages = [msg]

    if not msg:
        if isinstance(messages[0], list):
            msg = messages[0][0]
        else:
            msg = messages[0]
    messages_joined = log_array_to_string(messages)
    timestamp = f"{datetime.now(UTC).astimezone():%Y-%m-%d %H:%M:%S%z}"

    frame = inspect.currentframe()
    file = str(frame.f_code.co_filename)    # type: ignore[union-attr]
    function = str(frame.f_back.f_code.co_name)    # type: ignore[union-attr]
    lineno = frame.f_back.f_lineno    # type: ignore[union-attr]

    extra = {
        "messages": messages_joined,
        "timestamp": timestamp,
        "function": function,
        "file": f"{os.path.basename(file)}",
        "linenr": lineno,
    }
    __loglevel_to_logger(loglevel)(msg, extra=extra)
