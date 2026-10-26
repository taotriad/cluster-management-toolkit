# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of Kubernetes metrics.
"""

import csv
import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-locals
def get_metrics_list(**kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Get a list of Kubernetes metrics.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                filter ([str]): A list of metrics to return
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list of metrics
                (int): The status for the Kubernetes request
        Raises:
            ProgrammingError: Function called without kubernetes_helper
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")

    filters: list[str] = deep_get(kwargs, DictPath("filter"), [])

    vlist: list[dict[str, Any]] = []

    metrics, status = kh.get_metrics()

    # metrics are on the form:
    # apiserver_audit_event_total 0
    # aggregator_openapi_v2_regeneration_count{apiservice="*",reason="startup"} 0
    # apiserver_requested_deprecated_apis{group="autoscaling",removed_release="1.25",
    # resource="horizontalpodautoscalers",subresource="",version="v2beta1"} 1

    metrics_regex = re.compile(r"^([^{]*){([^}]*)}\s(\d+)$")

    metric_set = set()
    for line in metrics[1:]:
        if (re_tmp := metrics_regex.match(line)) is None:
            continue
        metric = re_tmp[1]
        count = re_tmp[3]
        metric_set.add(metric)

        if filters and metric not in filters:
            continue

        fields = [f"{x}" for x in next(csv.reader([re_tmp[2]], delimiter=",", quotechar="\""))]
        if not fields:
            continue
        d: dict[str, Any] = {
            "name": metric,
            "fields": {},
            "count": count,
            "metadata": {
                "uid": line,
            },
        }
        for field in fields:
            key_value = [f"{x}" for x in next(csv.reader([field], delimiter="=", quotechar="\""))]
            key, value = key_value
            d["fields"][key] = value.strip("\"")

        vlist.append(d)

    return vlist, status
