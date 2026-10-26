# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the status of a container.
"""

from typing import Any

from clustermanagementtoolkit.cmtlib import get_since
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


# pylint: disable-next=too-many-branches
def get_container_status(src_statuses: list[dict],
                         container: str) -> tuple[str, StatusGroup, int, str, int]:
    """
    Return the status for a container.

        Parameters:
            src_statuses (dict): A reference to either
                                 status#containerStatuses,
                                 status#initContainerStatuses, or
                                 status#ephemeralContainerStatuses
            container (str): The name of the container
        Returns:
            (str, StatusGroup, int, str, int):
                (str): Reason for the status
                (StatusGroup): Status group
                (int): How many times has the container been restarted
                (str): Status message, if any
                (int): Age of the container
    """
    reason = "UNKNOWN"
    status_group = StatusGroup.UNKNOWN
    restarts = 0
    message = ""
    age = -1

    if src_statuses is None or not src_statuses:
        return reason, status_group, -1, message, -1

    for container_status in src_statuses:
        if deep_get(container_status, DictPath("name")) == container:
            restarts = deep_get(container_status, DictPath("restartCount"))
            running = deep_get(container_status, DictPath("state#running"))
            ts = deep_get_with_fallback(container_status, [
                DictPath("state#terminated#finishedAt"),
                DictPath("lastState#terminated#finishedAt"),
                DictPath("state#running#startedAt")], "")
            age = get_since(timestamp_to_datetime(ts))

            if not deep_get(container_status, DictPath("ready")):
                status_group = StatusGroup.NOT_OK

                if running is not None:
                    reason = "Running"
                elif deep_get(container_status, DictPath("state#terminated")) is not None:
                    reason = deep_get(container_status,
                                      DictPath("state#terminated#reason"), "ErrNotSet")
                    if not deep_get(container_status, DictPath("state#terminated#exitCode")):
                        status_group = StatusGroup.DONE

                    if deep_get(container_status,
                                DictPath("state#terminated#message")) is not None:
                        message = deep_get(container_status,
                                           DictPath("state#terminated#message"), "").rstrip()
                else:
                    reason = deep_get(container_status,
                                      DictPath("state#waiting#reason"), "").rstrip()

                    if deep_get(container_status,
                                DictPath("state#waiting#message")) is not None:
                        message = deep_get(container_status,
                                           DictPath("state#waiting#message"), "").rstrip()
            else:
                if running is None:
                    reason = deep_get(container_status,
                                      DictPath("state#terminated#reason"), "").rstrip()

                    if deep_get(container_status,
                                DictPath("state#terminated#message")) is not None:
                        message = deep_get(container_status,
                                           DictPath("state#terminated#message"), "").rstrip()

                    if not deep_get(container_status, DictPath("state#terminated#exitCode")):
                        status_group = StatusGroup.DONE
                    else:
                        status_group = StatusGroup.NOT_OK
                else:
                    reason = "Running"
                    status_group = StatusGroup.OK
            break

    return reason, status_group, restarts, message, age


# pylint: disable-next=unused-argument
def datagetter_container_status(obj: dict[str, Any], **kwargs: Any) -> tuple[StatusGroup, dict]:
    """
    A datagetter that returns the status of a container.

        Parameters:
            obj (dict): The container object to get status for
            **kwargs (dict[str, Any]): Keyword arguments [unused]
    """
    if obj is None:
        return "UNKNOWN", {"status_group": StatusGroup.UNKNOWN}

    status = deep_get(obj, DictPath("status"))
    status_group = deep_get(obj, DictPath("status_group"))

    return status, {"status_group": status_group}
