# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return all objects belonging to a namespace.
Note: this is potentially *very* slow.
"""

import concurrent.futures
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit import listgetters_async


# pylint: disable-next=too-many-locals
def listgetter_namespaced_resources(obj: dict, **kwargs: Any) -> \
        tuple[list, str | int | list[StatusGroup]]:
    """
    Given a Namespace object, find all objects that belong to that Namespace.

        Parameters:
            obj (dict): The object to extract a list of data from
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                resources ([(str, str)]): A list of Kinds; if resources is not provided
                                          all namespaced resources will be searched
                label_selector (str): A label selector (optional)
                namespace (str): The name of the namespace to fetch namespaced resources for
                namespace_path (str): The path to get the name
                                      of the namespace to fetch namespaced resources for
        Returns:
            (([dict[str, Any]], int)): A list of Kubernetes objects of various Kinds
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    vlist = []
    status: str | int | list[StatusGroup] = 200

    namespaced_resources = deep_get(kwargs, DictPath("resources"),
                                    kh.get_list_of_namespaced_resources())
    label_selector = deep_get(kwargs, DictPath("label_selector"), "")

    kind = ("Namespace", "")
    namespace_path = deep_get(kwargs, DictPath("namespace_path"), "")
    namespace = deep_get(kwargs, DictPath("namespace"), "")
    namespace = deep_get(obj, DictPath(namespace_path), namespace)

    # We'll be one-shotting all of these, so we won't use reexecutor
    executor_ = concurrent.futures.ThreadPoolExecutor()
    executors = {}
    for kind in namespaced_resources:
        executors[kind] = executor_.submit(listgetters_async.get_kubernetes_list,
                                           kind=kind, namespace=namespace,
                                           kubernetes_helper=kh, kh_cache=kh_cache,
                                           label_selector=label_selector)
    for kind, ex in executors.items():
        vlist_, status_ = ex.result()
        if status_ != 200:
            # 404 means no resources found; this is OK
            if status_ != 404:
                status = status_
            continue
        if not vlist_:
            continue
        # We are (potentially) listing a lot of different types of resources,
        # and they do not contain kind/apiVersion, so it will be tricky to tell them apart...
        for obj_ in vlist_:
            obj_["__kind_tuple"] = kind
        vlist += vlist_
    executor_.shutdown(wait=False, cancel_futures=True)

    return vlist, status
