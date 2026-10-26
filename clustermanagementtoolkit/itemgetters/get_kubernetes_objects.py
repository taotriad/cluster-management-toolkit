# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns fields from Kubernetes objects.
"""

from typing import Any

from clustermanagementtoolkit.cmtlib import make_label_selector

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.kubernetes_resources import kubernetes_resources


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_kubernetes_objects(obj: dict, **kwargs: Any) -> list[tuple[str, ...]]:
    """
    Get a list of fields from Kubernetes objects.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                field_paths ([DictPath]): A list of DictPath to get data from
                kind (str): The Kubernetes kind to get objects from
                kind_path (str): The path to the Kubernetes kind to get objects from
                api_family (str): The Kubernetes API-family to get objects from
                api_family_path (str): The path to the Kubernetes API-family to get objects from
                name (str): The name to use in the selector
                name_path (str): The path to the name to use in the selector
                namespace (str): The namespace for the objects
                namespace_path (str): The path to the namespace for the objects
                selector_type (str): "field" or "label"
                selector (str): The selector to use; if name is provided the selector will use name,
                                otherwise the selector will be used bare
                selector_path (str): The path to the selector to use
                selector_none_on_empty: If selector_path has been specified, but the path yields
                                        an empty selector, setting this to true will yield an empty
                                        result instead of all objects.
        Returns:
            ([(str, str)]): A list of fields from Kubernetes objects
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    field_paths = deep_get(kwargs, DictPath("field_paths"), [])
    kind_path = deep_get(kwargs, DictPath("kind_path"))
    kind = deep_get(kwargs, DictPath("kind"))
    kind = deep_get(obj, DictPath(kind_path), kind)

    api_family_path = deep_get(kwargs, DictPath("api_family_path"))
    api_family = deep_get(kwargs, DictPath("api_family"), "")
    api_family = deep_get(obj, DictPath(api_family_path), api_family)

    api_version_path = deep_get(kwargs, DictPath("api_version_path"))
    api_version = deep_get(kwargs, DictPath("api_version"), "")
    api_version = deep_get(obj, DictPath(api_version_path), api_version)

    guess_kind = deep_get(kwargs, DictPath("guess_kind"), True)
    remove_after_use = False

    namespace_path = deep_get(kwargs, DictPath("namespace_path"))
    namespace = deep_get(kwargs, DictPath("namespace"), "")
    namespace = deep_get(obj, DictPath(namespace_path), namespace)
    namespaced_resource = deep_get(kwargs, DictPath("namespaced_resource"), True)

    name_path = deep_get(kwargs, DictPath("name_path"))
    name = deep_get(kwargs, DictPath("name"))
    name = deep_get(obj, DictPath(name_path), name)

    selector_type = deep_get(kwargs, DictPath("selector_type"), "label")
    selector_str = deep_get(kwargs, DictPath("selector"), "")
    selector_path = deep_get(kwargs, DictPath("selector_path"), "")
    selector_none_on_empty = deep_get(kwargs, DictPath("selector_none_on_empty"), False)

    label_selector = ""
    field_selector = ""

    if selector_str or selector_path:
        if selector_path:
            selector = deep_get(obj, DictPath(selector_path), "")
            if not selector and selector_none_on_empty:
                return []
            if isinstance(selector, dict):
                selector = make_label_selector(selector)
        elif name:
            selector = f"{selector_str}={name}"
        else:
            selector = selector_str

        if selector_type == "label":
            label_selector = selector
        else:
            field_selector = selector

    if not guess_kind:
        lkind = kind.lower()
        if not lkind.endswith("s"):
            lkind = f"{lkind}s"
        lapi_family = f"apis/{api_family}/"
        if api_version:
            lapi_family = f"{lapi_family}{api_version}/"
        # Create a temporary Kubernetes resource
        if (kind, api_family) not in kubernetes_resources:
            kubernetes_resources[(kind, api_family)] = {
                "api_paths": [lapi_family],
                "api": lkind,
                "namespaced": namespaced_resource,
            }
            remove_after_use = True

    vlist, status = \
        kh.get_list_by_kind_namespace((kind, api_family),
                                      namespace,
                                      label_selector=label_selector,
                                      field_selector=field_selector,
                                      resource_cache=kh_cache)

    tmp: list[Any] = []
    if vlist is None or status != 200:
        # This ensures that we fall through and remove temporary resources
        vlist = []

    for item in vlist:
        entry = []
        for field_path in field_paths:
            entry.append(deep_get(item, DictPath(field_path)))
        tmp.append({"fields": tuple(entry), "ref": item})

    if remove_after_use:
        kubernetes_resources.pop((kind, api_family), None)

    return tmp
