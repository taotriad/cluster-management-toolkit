# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the status of a Persistent Volume.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get


def get_pv_status(obj: dict[str, Any]) -> tuple[str, StatusGroup]:
    """
    Given a Persistent Volume object, return its status.

        Parameters:
            obj (dict[str, Any]): The Persistent Volume object
        Returns:
            ((str, StatusGroup)):
                (str): The status of the Persistent Volume
                (StatusGroup): The StatusGroup of the status
    """
    phase: str = deep_get(obj, DictPath("status#phase"), "")

    if phase in ("Bound", "Available"):
        reason = phase
        status_group = StatusGroup.OK
    elif phase == "Released":
        reason = phase
        status_group = StatusGroup.DONE
    elif phase == "Pending":
        reason = phase
        status_group = StatusGroup.PENDING
    else:
        # phase == "Failed"
        reason = deep_get(obj, DictPath("status#reason"), "").strip()
        status_group = StatusGroup.NOT_OK
    return reason, status_group
