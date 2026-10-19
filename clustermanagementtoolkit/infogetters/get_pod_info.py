# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmtlib import get_since
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit import datagetters

from clustermanagementtoolkit.infogetters.format_controller import format_controller

from clustermanagementtoolkit import itemgetters

from clustermanagementtoolkit.kubernetes_helper import get_containers
from clustermanagementtoolkit.kubernetes_helper import get_controller_from_owner_references
from clustermanagementtoolkit.kubernetes_helper import get_pod_restarts_total


# pylint: disable-next=too-many-locals
def get_pod_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Pods.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                vlist ([dict[str, Any]]): The list of Pod info
                in_depth_node_status (bool): Should in-depth node status be shown?
                extra_vars (dict): Extra variables
                filters ([dict]): A dict of filters to apply
        Returns:
            ([dict]): A list with info
    """
    in_depth_node_status: bool = deep_get(kwargs, DictPath("in_depth_node_status"), True)
    extra_vars: dict[str, Any] = deep_get(kwargs, DictPath("extra_vars"),
                                          {"show_kind": "", "show_evicted": True})
    filters: list[dict[str, Any]] = deep_get(kwargs, DictPath("filters"), [])
    info: list[dict] = []

    if not (vlist := deep_get(kwargs, DictPath("vlist"))):
        return []

    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    for obj in vlist:
        skip = False

        # Sadly field_labels do not support all fields we might want to filter on,
        # so we have to complicate things a bit
        for key, value in filters:
            ovalue = deep_get(obj, DictPath(key), None)
            if ovalue is None or ovalue != value:
                skip = True
                break

        if skip:
            continue

        phase = deep_get(obj, DictPath("status#phase"))
        reason = deep_get(obj, DictPath("status#reason"), "").rstrip()

        if (not deep_get(extra_vars, DictPath("show_evicted"), False)
                and phase == "Failed" and reason == "Evicted"):
            continue

        namespace = deep_get(obj, DictPath("metadata#namespace"))
        name = deep_get(obj, DictPath("metadata#name"))
        ref = obj
        nodename = deep_get(obj, DictPath("spec#nodeName"), "<none>")
        status, status_group = \
            datagetters.get_pod_status(obj, kubernetes_helper=kh,
                                       kh_cache=kh_cache,
                                       in_depth_node_status=in_depth_node_status)

        if in_depth_node_status:
            timestamp = \
                timestamp_to_datetime(deep_get(obj, DictPath("metadata#creationTimestamp")))
            age = get_since(timestamp)

            owr = deep_get(obj, DictPath("metadata#ownerReferences"), [])
            controller_ = get_controller_from_owner_references(owr)
            show_kind = deep_get(extra_vars, DictPath("show_kind"), "").lower()
            controller = format_controller(controller_, show_kind)

            pod_ip = deep_get(obj, DictPath("status#podIP"), "<unset>")
            pod_restarts, restarted_at = get_pod_restarts_total(obj)
            if restarted_at == -1:
                last_restart = -1
            else:
                last_restart = get_since(restarted_at)
            container_list = deep_get(obj, DictPath("spec#containers"), [])
            container_statuses = deep_get(obj, DictPath("status#containerStatuses"), [])
            init_container_list = deep_get(obj, DictPath("spec#initContainers"), [])
            init_container_statuses = deep_get(obj, DictPath("status#initContainerStatuses"), [])
            tolerations = itemgetters.get_tolerations(obj)
            containers = get_containers(containers=init_container_list,
                                        container_statuses=init_container_statuses)
            containers += get_containers(containers=container_list,
                                         container_statuses=container_statuses)

            info.append({
                "namespace": namespace,
                "name": name,
                # The reference to the "true" resource object
                "ref": ref,
                "status": status,
                "status_group": status_group,
                "node": nodename,
                "pod_ip": pod_ip,
                "age": age,
                "restarts": pod_restarts,
                "last_restart": last_restart,
                "controller": controller,
                "tolerations": tolerations,
                "containers": containers,
            })
        else:
            # This is to speed up the cluster overview,
            # which doesn't use most of this information anyway;
            # for clusters with a huge amount of pods
            # this can make a quite significant difference.
            info.append({
                "namespace": namespace,
                "name": name,
                # The reference to the "true" resource object
                "ref": ref,
                "status": status,
                "status_group": status_group,
                "node": nodename,
            })
    return info
