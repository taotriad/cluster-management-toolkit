# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() to get status tuples.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get


def get_obj_status_tuple(obj: dict, ipath: dict, values: list[Any], **kwargs: Any) -> list[Any]:
    """
    A helper for get_obj() that compacts a list of integers into a list of integer ranges.

        Parameters:
            obj (dict): The object to extract data from
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            ([Any]):
                ([Any]): A list of objects
    """
    field_name = deep_get(kwargs, DictPath("field_name"), "<unset>")
    kh = deep_get(kwargs, DictPath("kubernetes_helper"))
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    if "lookup" in ipath:
        lookup_kind = deep_get(ipath, DictPath("lookup#kind"))
        lookup_api_family = deep_get(ipath, DictPath("lookup#api_family"))
        lookup_status = deep_get(ipath, DictPath("lookup#status"))
    else:
        raise ValueError(f"Field {field_name}: currently status_tuple "
                         "only supports 'lookup'")
    path = deep_get(ipath, DictPath("path"))
    value = deep_get(obj, DictPath(path))
    tmp = kh.get_ref_by_kind_name_namespace((lookup_kind, lookup_api_family),
                                            value, "", resource_cache=kh_cache)
    if lookup_status == "highlight":
        if tmp is None:
            status_group = StatusGroup.NOT_OK
        else:
            status_group = StatusGroup.OK
        value = (value, status_group)
    elif lookup_status == "message":
        if tmp is None:
            value = (deep_get(ipath, DictPath("lookup#messages#not_ok")),
                     StatusGroup.NEUTRAL)
        else:
            value = (deep_get(ipath, DictPath("lookup#messages#ok")),
                     StatusGroup.NEUTRAL)
    values.append((value, "raw"))
    return values
