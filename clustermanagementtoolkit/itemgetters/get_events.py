# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns a list of events.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


def get_events(obj: dict, **kwargs: Any) -> list[dict]:
    """
    Get a list of events.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            ([dict]): A list of events
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    event_list = []

    kind = deep_get(obj, DictPath("kind"))
    api_version = deep_get(obj, DictPath("apiVersion"), "")
    name = deep_get(obj, DictPath("metadata#name"))
    namespace = deep_get(obj, DictPath("metadata#namespace"), "")
    tmp = kh.get_events_by_kind_name_namespace(kh.kind_api_version_to_kind(kind, api_version),
                                               name, namespace, resource_cache=kh_cache)
    for event in tmp:
        event_list.append({
            "fields": event,
        })

    return event_list
