# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given error information from an Ansible run, return a suitable error message.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-branches
def ansible_extract_failure(retval: int, error_msg_lines: list[str], **kwargs: Any) -> str:
    """
    Given error information from an Ansible run, return a suitable error message.

        Parameters:
            retval (int): The retval from the run
            error_msg_lines ([str]): A list of error messages
            **kwargs (dict[str, Any]): Keyword arguments
                skipped (bool): Was the task skipped?
                unreachable (bool): Was the target unreachable?
        Returns:
            (str): A status string
    """
    skipped: bool = deep_get(kwargs, DictPath("skipped"), False)
    unreachable: bool = deep_get(kwargs, DictPath("unreachable"), False)

    status = ""

    if unreachable:
        if error_msg_lines:
            for line in error_msg_lines:
                if "Name or service not known" in line:
                    status = "COULD NOT RESOLVE"
                    break
                if "Permission denied" in line:
                    status = "PERMISSION DENIED"
                    break
                if "No route to host" in line:
                    status = "NO ROUTE TO HOST"
                    break
                if "Connection timed out" in line:
                    status = "CONNECTION TIMED OUT"
                    break
            if not status:
                status = "UNREACHABLE (unknown error)"
        else:
            status = "UNREACHABLE (unknown reason)"
    elif skipped:
        status = "SKIPPED"
    else:
        if retval:
            if error_msg_lines:
                for line in error_msg_lines:
                    if "The module failed to execute correctly" in line:
                        status = "MISSING INTERPRETER?"
                        break
                if not status:
                    status = "FAILED (unknown error)"
            if not status:
                status = "FAILED (unknown reason)"
        else:
            status = "SUCCESS"

    return status
