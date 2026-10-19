# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get


def split_bracketed_severity(message: str, **kwargs: Any) -> tuple[LogLevel, str]:
    """
    Remove a bracketed severity prefix from a string.

        Parameters:
            message: A string to strip a severity prefix from
            **kwargs (dict[str, Any]): Keyword arguments
                options:
                    default (str): The default severity to use if no
                                   LogLevel prefix can be found
        Returns:
            (LogLevel, str):
                (LogLevel): The extracted LogLevel
                (str): The input string with the severity prefix removed
    """
    default: str = deep_get(kwargs, DictPath("options#severity#default"), "default")

    severities: dict[str, LogLevel] = {
        "[default]": LogLevel.DEFAULT,
        "[fatal]": LogLevel.CRIT,
        # This is for ingress-nginx;
        # normally (syslog) crit is more severe than alert,
        # and emerg is the most severe severity.
        # This doesn't seem to apply to ingress-nginx,
        # where alert is used equivalent to error,
        # and emerg is used more akin to error.
        "[emerg]": LogLevel.ERR,
        "[alert]": LogLevel.ERR,
        "[error]": LogLevel.ERR,
        "[err]": LogLevel.ERR,
        "[warning]": LogLevel.WARNING,
        "[warn]": LogLevel.WARNING,
        "[notice]": LogLevel.NOTICE,
        "[info]": LogLevel.INFO,
        "[system]": LogLevel.INFO,  # MySQL seems to have its own loglevels
        "[note]": LogLevel.INFO,    # none of which makes every much sense
        "[verbose]": LogLevel.DEBUG,  # whereabouts has its own loglevels; it has both
                                      # verbose and debug; we don't, so just treat them the same
        "[debug]": LogLevel.DEBUG,
    }

    if (re_tmp := re.match(r"^(\[[A-Za-z]+?\]) ?(.*)", message)) is not None:
        if (severity := deep_get(severities, DictPath(re_tmp[1].lower()))) is not None:
            message = re_tmp[2]
        else:
            severity = deep_get(severities, DictPath(f"[{default}]"), LogLevel.DEFAULT)
    else:
        severity = deep_get(severities, DictPath(f"[{default}]"), LogLevel.DEFAULT)

    return severity, message
