# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the total number of times that all containers in a pod have restarted
and the timestamp of the latest restart.
"""

from datetime import datetime
from typing import Any, cast

from clustermanagementtoolkit.cmtlib import timestamp_to_datetime

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


def get_pod_restarts_total(pod: dict[str, Any]) -> tuple[int, int | datetime]:
    """
    Given a Pod object, return the total number of restarts for all containers
    as well as the timestamp of the latest restart.

        Parameters:
            pod (dict): The pod to return information about
        Returns:
            (int, int|datetime):
                (int): The number of restarts
                (int|datetime): The timestamp for the last restart
                        or -1 if number of restarts = 0
    """
    restarts: int = 0
    restarted_at: int | datetime = -1

    # for status in deep_get(pod, DictPath("status#initContainerStatuses"), []) \
    #               + deep_get(pod, DictPath("status#containerStatuses"), []):
    for status in deep_get(pod, DictPath("status#containerStatuses"), []):
        restart_count = deep_get(status, DictPath("restartCount"), 0)
        restarts += restart_count
        if restart_count:
            restart_ts = deep_get_with_fallback(status,
                                                [DictPath("state#running#startedAt"),
                                                 DictPath("lastState#terminated#finishedAt")])
            started_at = timestamp_to_datetime(restart_ts)
            if started_at is not None \
                    and (restarted_at == -1 or cast(datetime, restarted_at) < started_at):
                restarted_at = started_at

    if not restarts:
        restarted_at = -1
    return restarts, restarted_at
