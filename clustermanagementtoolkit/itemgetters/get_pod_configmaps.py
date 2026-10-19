# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any, cast

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-locals,too-many-branches
def get_pod_configmaps(obj: dict, **kwargs: Any) -> list[dict[str, Any]] | None:
    """
    Get a list of all pods referencing a configmap.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                cm_namespace (str|[str]): The namespace/path to the ConfigMap namespace
                cm_name (str|[str]): The name/path to the ConfigMap name
                pod_name (str): The name of the pod
        Returns:
            ([dict[str, Any]]):
                ((str, str)):
                    (str): ConfigMap namespace
                    (str): Pod name
                (dict): The Pod object that matches the namespace
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    cm_namespace = deep_get(kwargs, DictPath("cm_namespace"))
    if isinstance(cm_namespace, list):
        cm_namespace = deep_get_with_fallback(obj, cm_namespace)
    cm_name = deep_get(kwargs, DictPath("cm_name"))
    if isinstance(cm_name, list):
        cm_name = deep_get_with_fallback(obj, cm_name)
    pod_name = deep_get(kwargs, DictPath("pod_name"))
    if isinstance(pod_name, list):
        pod_name = deep_get_with_fallback(obj, pod_name)
    if cm_namespace is None or cm_name is None:
        return None

    vlist = []

    field_selector = ""
    if pod_name is not None and pod_name:
        field_selector = f"metadata.name={pod_name}"

    plist, _status = kh.get_list_by_kind_namespace(("Pod", ""),
                                                   cm_namespace,
                                                   field_selector=field_selector,
                                                   resource_cache=kh_cache)
    plist = cast(list, plist)

    for item in plist:
        pod_name = deep_get(item, DictPath("metadata#name"), "")
        matched = False
        for volume in deep_get(item, DictPath("spec#volumes"), []):
            if deep_get(volume, DictPath("configMap#name"), "") == cm_name:
                matched = True
                vlist.append({"fields": (cm_namespace, pod_name), "ref": item})
                break
            for source in deep_get(volume, DictPath("projected#sources"), []):
                if deep_get(source, DictPath("configMap#name"), "") == cm_name:
                    matched = True
                    vlist.append({"fields": (cm_namespace, pod_name), "ref": item})
                    break
            if matched:
                break
        if matched:
            continue
        for container in deep_get(item, DictPath("spec#containers"), []):
            for env in deep_get(container, DictPath("env"), []):
                if deep_get(env, DictPath("ValueFrom#configMapKeyRef#name"), "") == cm_name:
                    matched = True
                    vlist.append({"fields": (cm_namespace, pod_name), "ref": item})
                    break
            if matched:
                break
            for env_from in deep_get(container, DictPath("envFrom"), []):
                if deep_get(env_from, DictPath("configMapKeyRef#name"), "") == cm_name:
                    vlist.append({"fields": (cm_namespace, pod_name), "ref": item})
                    break

    if not vlist:
        return None

    return vlist
