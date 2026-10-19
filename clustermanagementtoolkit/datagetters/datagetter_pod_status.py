# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return status for a Pod.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.datagetters.datagetter_container_status import get_container_status

from clustermanagementtoolkit.kubernetes_helper import get_node_status


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_pod_status(obj: dict[str, Any], **kwargs: Any) -> tuple[str, StatusGroup]:
    """
    Get status for a Pod.

        Parameters:
            obj (dict): The pod object to return status for
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                in_depth_node_status (bool): Return more detailed node status? Will check whether
                                             the associate node is available
        Returns:
            (str, StatusGroup):
                (str): The phase of the pod
                (StatusGroup): The StatusGroup of the pod
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    in_depth_node_status = deep_get(kwargs, DictPath("in_depth_node_status"), True)

    if deep_get(obj, DictPath("metadata#deletionTimestamp")) is not None:
        status = "Terminating"
        status_group = StatusGroup.PENDING
        return status, status_group

    phase = deep_get(obj, DictPath("status#phase"))

    if phase == "Pending":
        status = phase
        status_group = StatusGroup.PENDING

        # Any containers in ContainerCreating or similar?
        for condition in deep_get(obj, DictPath("status#conditions"), []):
            condition_type = deep_get(condition, DictPath("type"))
            condition_status = deep_get(condition, DictPath("status"))
            reason = deep_get(condition, DictPath("reason"), "")

            if condition_type == "PodScheduled" and \
                    condition_status == "False" and reason == "Unschedulable":
                status = reason
                status_group = StatusGroup.NOT_OK
                break

            if condition_type == "ContainersReady" and condition_status == "False":
                for container in deep_get(obj, DictPath("status#initContainerStatuses"), []):
                    if deep_get(container, DictPath("ready")):
                        continue
                    reason = deep_get(container, DictPath("state#waiting#reason"), "").rstrip()
                    if reason is None or not reason:
                        continue
                    if reason in ("CrashLoopBackOff", "ErrImageNeverPull", "ErrImagePull",
                                  "ImagePullBackOff", "InvalidImageName"):
                        status_group = StatusGroup.NOT_OK
                    status = f"Init:{reason}"
                    break
                for container in deep_get(obj, DictPath("status#containerStatuses"), []):
                    if deep_get(container, DictPath("ready")):
                        continue
                    reason = deep_get(container, DictPath("state#waiting#reason"), "").rstrip()
                    if reason is None or not reason:
                        continue
                    if reason in ("CrashLoopBackOff", "ErrImageNeverPull", "ErrImagePull",
                                  "ImagePullBackOff", "InvalidImageName"):
                        status_group = StatusGroup.NOT_OK
                    status = reason
                    break

        return status, status_group

    if phase == "Running":
        status = "Running"
        status_group = StatusGroup.OK

        # Any container failures?
        for condition in deep_get(obj, DictPath("status#conditions"), []):
            condition_type = deep_get(condition, DictPath("type"))
            condition_status = deep_get(condition, DictPath("status"))

            if condition_type == "Ready" and condition_status == "False":
                status_group = StatusGroup.NOT_OK
                status = "NotReady"
                # Can we get more info? Is the host available?
                if in_depth_node_status:
                    node_name = deep_get(obj, DictPath("spec#nodeName"))
                    node = kh.get_ref_by_kind_name_namespace(("Node", ""), node_name, "",
                                                             resource_cache=kh_cache)
                    node_status = get_node_status(node)
                    if node_status[0] == "Unreachable":
                        status = "NodeUnreachable"
                break

            if condition_type == "ContainersReady" and condition_status == "False":
                status_group = StatusGroup.NOT_OK

                for container in deep_get(obj, DictPath("status#initContainerStatuses"), []):
                    status, status_group, _restarts, _message, _age = \
                        get_container_status(deep_get(obj,
                                                      DictPath("status#initContainerStatuses")),
                                             deep_get(container, DictPath("name")))

                    # If we have a failed container,
                    # break here
                    if status_group == StatusGroup.NOT_OK:
                        break

                for container in deep_get(obj, DictPath("status#containerStatuses"), []):
                    status, status_group, _restarts, _message, _age = \
                        get_container_status(deep_get(obj, DictPath("status#containerStatuses")),
                                             deep_get(container, DictPath("name")))
                    # If we have a failed container,
                    # break here
                    if status_group == StatusGroup.NOT_OK:
                        break

        return status, status_group

    if phase == "Failed":
        # Failed
        status_group = StatusGroup.NOT_OK
        status = deep_get(obj, DictPath("status#reason"), phase).rstrip()
        return status, status_group

    # Succeeded
    status_group = StatusGroup.DONE
    return phase, status_group


def datagetter_pod_status(obj: dict[str, Any], **kwargs: Any) -> tuple[str, dict]:
    """
    A datagetter that returns the status for a pod.

        Parameters:
            obj (dict): The pod object to return pod status for
            **kwargs (dict[str, Any]): Keyword arguments
                kh (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                default (Any): Data to return if the object is None
                in_depth_node_status (bool): Return more detailed node status? Will check whether
                                             the associate Node is available
        Returns:
            (str, StatusGroup):
                (str): The phase of the pod
                    (dict["status_group", StatusGroup]):
                        (StatusGroup): The StatusGroup of the pod
    """
    default = deep_get(kwargs, DictPath("default"))

    if obj is None:
        return default, {"status_group": StatusGroup.UNKNOWN}

    status, status_group = get_pod_status(obj, **kwargs)

    return status, {"status_group": status_group}
