# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generic infogetter usable for most data.
"""

import sys
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.infogetters.get_obj import get_obj


def generic_infogetter(**kwargs: Any) -> list[dict]:
    """
    Generic getter for information from an object.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                _vlist ([dict]): A list of already populated entries
                field_dict (dict): The dict containing the description of the field
                field_names ([str]): The names of the fields to populate
                field_index (str): The index for the field list
                filters (dict): The filters to apply
                extra_data (dict): Extra data to add to the obj
                caller_obj (dict): Used for lookups when doing path substitutions
        Returns:
            ([dict]): A list of dicts with the data for all fields in the field_names list
    """
    kh = deep_get(kwargs, DictPath("kubernetes_helper"))
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    info: list[dict] = []

    # Generate an empty entry
    if not (vlist := deep_get(kwargs, DictPath("_vlist"), [])):
        return []

    field_dict = deep_get(kwargs, DictPath("_field_dict"), {})
    field_names = deep_get(kwargs, DictPath("_field_names"), [])
    field_index = deep_get(kwargs, DictPath("_field_index"), "Normal")
    filters = deep_get(kwargs, DictPath("_filters"), {})
    extra_data = deep_get(kwargs, DictPath("extra_data"), {})
    caller_obj = deep_get(kwargs, DictPath("caller_obj"), {})

    if not field_dict or not field_names:
        sys.exit(f"generic_infogetter() received empty field_dict {field_dict} "
                 f"or field_names {field_names}; this is a programming error")

    # If we know the view we can use it to get overrides from cmt.yaml
    view = deep_get(kwargs, DictPath("_view"), "")
    for obj in vlist:
        if extra_data:
            obj["_extra_data"] = extra_data
        deleted = False
        if deep_get(obj, DictPath("metadata#deletionTimestamp")) is not None:
            deleted = True
        tmp = get_obj(obj, field_dict=field_dict, field_names=field_names, field_index=field_index,
                      view=view, filters=filters, deleted=deleted, caller_obj=caller_obj,
                      kubernetes_helper=kh, kh_cache=kh_cache)
        if tmp is None:
            continue

        info.append(tmp)

    return info
