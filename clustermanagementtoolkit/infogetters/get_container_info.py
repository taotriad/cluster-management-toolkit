# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.infogetters.__get_container_info import __get_container_info

from clustermanagementtoolkit.kubernetes_helper import KubernetesResourceCache


# pylint: disable-next=too-many-locals
def get_container_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for containers.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            ([dict]): A list with info
    """
    if (kh_ := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache_: KubernetesResourceCache | None = deep_get(kwargs, DictPath("kh_cache"))

    info: list[dict] = []
    containers: dict = {}

    # There's no direct way to get a list of unique containers
    # as defined by the tuple (name, type, version, image_id),
    # so we need to iterate the list of all pods and extract this
    # information.
    vlist, status = kh_.get_list_by_kind_namespace(("Pod", ""), "", resource_cache=kh_cache_)
    if status != 200:
        return info

    for obj in vlist:
        tmp = __get_container_info(obj, "InitContainer",
                                   DictPath("spec#initContainers"),
                                   DictPath("status#initContainerStatuses"))
        for key, value in tmp.items():
            instances = value["instances"]
            pod_references = value["pod_references"]
            if key not in containers:
                containers[key] = {}
                containers[key]["instances"] = 0
                containers[key]["pod_references"] = []

            containers[key]["instances"] += instances
            containers[key]["pod_references"] += pod_references
        tmp = __get_container_info(obj, "Container",
                                   DictPath("spec#containers"),
                                   DictPath("status#containerStatuses"))
        for key, value in tmp.items():
            instances = value["instances"]
            pod_references = value["pod_references"]
            if key not in containers:
                containers[key] = {}
                containers[key]["instances"] = 0
                containers[key]["pod_references"] = []

            containers[key]["instances"] += instances
            containers[key]["pod_references"] += pod_references

    for name, container_type, image_version, image_id in containers:
        pod_references = containers[(name, container_type,
                                     image_version, image_id)]["pod_references"]
        pods = []
        for pod in pod_references:
            pods.append((deep_get(pod, DictPath("metadata#namespace")),
                         deep_get(pod, DictPath("metadata#name"))))
        instances = containers[(name, container_type, image_version, image_id)]["instances"]
        info.append({
            "name": name,
            # This replaces ref
            "ref": {
                "name": name,
                "container_type": container_type,
                "image_version": image_version,
                "image_id": image_id,
                "pod_references": pod_references,
            },
            "container_type": container_type,
            "image_version": image_version,
            "instances": instances,
            "image_id": image_id,
            "pods": pods,
            "pod_references": pod_references,
        })
    return info
