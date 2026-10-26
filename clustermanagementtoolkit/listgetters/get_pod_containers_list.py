# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of pod containers.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.datagetters import get_container_status


# pylint: disable-next=too-many-locals,too-many-branches
def get_pod_containers_list(**kwargs: Any) -> tuple[list[dict[str, Any]], int | str]:
    """
    Get a list of all pods with a separate entry for every container.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list of Kubernetes objects
                (int): The status for the Kubernetes request
        Raises:
            ProgrammingError: Function called without kubernetes_helper
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    vlist: list[dict[str, Any]] = []
    _vlist, status = kh.get_list_by_kind_namespace(("Pod", ""), "", resource_cache=kh_cache)

    if status == 200:
        for obj in _vlist:
            namespace = deep_get(obj, DictPath("metadata#namespace"))
            name = deep_get(obj, DictPath("metadata#name"))
            node_name = deep_get(obj, DictPath("spec#nodeName"))
            uid = deep_get(obj, DictPath("metadata#uid"))
            for container in deep_get(obj, DictPath("spec#containers"), []):
                container_name = deep_get(container, DictPath("name"))
                reason, status_group, _restarts, _message, _age = \
                    get_container_status(deep_get(obj, DictPath("status#containerStatuses")),
                                         container_name)
                container_status = None
                for container_status in deep_get(obj, DictPath("status#containerStatuses"), []):
                    if deep_get(container_status, DictPath("name")) == container_name:
                        break
                if container_status is not None:
                    image = deep_get(container_status, DictPath("image"), "")
                    if not image:
                        image = deep_get(container, DictPath("image"), "")
                    image_id = deep_get(container_status, DictPath("imageID"), "")
                else:
                    image = "<unavailable>"
                    image_id = "<unavailable>"
                vlist.append({
                    "namespace": namespace,
                    "name": name,
                    "container": container_name,
                    "container_type": "Container",
                    "status": reason,
                    "status_group": status_group,
                    "node_name": node_name,
                    "image": image,
                    "image_id": image_id,
                    "metadata": {
                        "uid": f"{uid}-{container_name}",
                    },
                })

            for container in deep_get(obj, DictPath("spec#initContainers"), []):
                container_name = deep_get(container, DictPath("name"))
                reason, status_group, _restarts, _message, _age = \
                    get_container_status(deep_get(obj, DictPath("status#initContainerStatuses")),
                                         container_name)
                container_status = None
                for container_status in deep_get(obj, DictPath("status#initContainerStatuses"), []):
                    if deep_get(container_status, DictPath("name")) == container_name:
                        break
                if container_status is not None:
                    image = deep_get(container, DictPath("image"), "")
                    image_id = deep_get(container_status, DictPath("imageID"), "")
                else:
                    image = "<unavailable>"
                    image_id = "<unavailable>"
                vlist.append({
                    "namespace": namespace,
                    "name": name,
                    "container_type": "InitContainer",
                    "container": container_name,
                    "status": reason,
                    "status_group": status_group,
                    "node_name": node_name,
                    "image": image,
                    "image_id": image_id,
                    "metadata": {
                        "uid": f"{uid}-{container_name}-init",
                    },
                })

    return vlist, status
