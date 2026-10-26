# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper for get_obj() that does Kubernetes object lookups.
"""

from typing import Any

from clustermanagementtoolkit.cmtlib import make_label_selector

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.infogetters.when_filter import when_filter


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_obj_lookup(obj: dict, path: list[DictPath], ipath: dict,
                   values: list[Any], **kwargs: Any) -> tuple[list[Any], bool]:
    """
    A helper for get_obj() that does Kubernetes object lookups.

        Parameters:
            obj (dict): The object to extract data from
            path ([DictPath]): A path with fallbacks
            ipath (dict): The subpath to extra data from
            values (list[Any]): The list of values to append the data to
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                default (Any): The value to return if no matches are found
        Returns:
            (([Any], bool)):
                ([Any]): A list of objects
                (bool): True on successful lookup, False on failure
    """
    default = deep_get(kwargs, DictPath("default"))
    kh = deep_get(kwargs, DictPath("kubernetes_helper"))
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    vtype = deep_get(ipath, DictPath("type"), "raw")
    tmp_lookup_selector: str = ""
    tmp_lookup_field_selector: str = ""
    if len(path) == 5:
        lookup_kind, lookup_api_group, lookup_namespace, \
            lookup_name, tmp_lookup_selector = path
    elif len(path) == 6:
        lookup_kind, lookup_api_group, lookup_namespace, \
            lookup_name, tmp_lookup_selector, tmp_lookup_field_selector = path
    if isinstance(lookup_kind, list):
        lookup_kind = deep_get_with_fallback(obj, lookup_kind, "")
    if isinstance(lookup_api_group, list):
        lookup_api_group = deep_get_with_fallback(obj, lookup_api_group, "")
    if isinstance(lookup_namespace, list):
        lookup_namespace = deep_get_with_fallback(obj, lookup_namespace, "")
    if isinstance(lookup_name, list):
        lookup_name = deep_get_with_fallback(obj, lookup_name, "")
    if not tmp_lookup_selector:
        lookup_selector = ""
    else:
        _lookup_selector = {}
        for ls in tmp_lookup_selector:
            ls_key = ls[0]
            ls_value = ls[1]
            if isinstance(ls_value, list):
                ls_value = deep_get_with_fallback(obj, ls_value)
            _lookup_selector[ls_key] = ls_value
        lookup_selector = make_label_selector(_lookup_selector)
    if not tmp_lookup_field_selector:
        lookup_field_selector = ""
    else:
        _lookup_selector = {}
        for ls in tmp_lookup_field_selector:
            ls_key = ls[0]
            ls_value = ls[1]
            if isinstance(ls_value, list):
                ls_value = deep_get_with_fallback(obj, ls_value)
            _lookup_selector[ls_key] = ls_value
        lookup_field_selector = make_label_selector(_lookup_selector)

    try:
        if not lookup_name:
            lookup_obj, _status = \
                kh.get_list_by_kind_namespace((lookup_kind, lookup_api_group),
                                              lookup_namespace,
                                              label_selector=lookup_selector,
                                              field_selector=lookup_field_selector,
                                              resource_cache=kh_cache)
        else:
            lookup_obj = \
                kh.get_ref_by_kind_name_namespace((lookup_kind, lookup_api_group),
                                                  lookup_name, lookup_namespace,
                                                  resource_cache=kh_cache)
    except NameError:
        unknown = deep_get(ipath, DictPath("unknown"), "Unknown Kind")
        values.append((unknown, "raw"))
        return values, False
    if lookup_obj is None \
            or isinstance(lookup_obj, dict) and not when_filter(ipath, item=lookup_obj):
        values.append((default, "raw"))
        return values, False
    subpaths = deep_get(ipath, DictPath("subpaths"), [])
    value: Any = []
    if subpaths:
        tmp = []
        if isinstance(lookup_obj, dict):
            lookup_obj = [lookup_obj]

        for _lookup_obj in lookup_obj:
            for subpath in subpaths:
                tmp.append(deep_get(_lookup_obj, DictPath(subpath)))
        if len(tmp) == 1:
            value.append(tmp[0])
        else:
            value.append(tuple(tmp))

    if not value:
        value = default

    substitute = deep_get(ipath, DictPath("substitute"))
    if substitute is not None:
        value = substitute
    if vtype == "len" and value:
        if len(value) > 1:
            value = len(value)
        elif isinstance(value, list) and isinstance(value[0], tuple):
            value = len(value[0])
    values.append((value, "raw"))
    return values, True
