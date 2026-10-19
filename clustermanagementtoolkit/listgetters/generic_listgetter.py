# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Fetch data from Kubernetes, and optionally filter it, before returning the data.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.listgetters.filter_list_entry import filter_list_entry


# listview, listpad
def generic_listgetter(kind: tuple[str, str], namespace: str,
                       **kwargs: Any) -> tuple[list[dict[str, Any]], int | str]:
    """
    Fetch data from Kubernetes.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                label_selector (str): A comma-separated string with a list of label selectors
                field_selector (str): A comma-separated string with a list of field selectors
                filters (dict[str, Any]): Filters to apply to the list of objects
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

    label_selector = deep_get(kwargs, DictPath("label_selector"), "")
    field_selector = deep_get(kwargs, DictPath("field_selector"), "")
    filters = deep_get(kwargs, DictPath("filters"), [])
    vlist, status = kh.get_list_by_kind_namespace(kind, namespace, label_selector=label_selector,
                                                  field_selector=field_selector,
                                                  resource_cache=kh_cache)
    if not vlist or status != 200 or not filters:
        return vlist, status

    vlist2 = []

    for item in vlist:
        if filter_list_entry(item, deep_get(kwargs, DictPath("_obj"), {}), filters):
            continue
        vlist2.append(item)

    return vlist2, status
