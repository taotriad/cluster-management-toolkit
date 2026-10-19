# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A fieldgetter that provides the version from a Kubernetes object.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmtlib import make_label_selector

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def fieldgetter_kubernetes_object_version(**kwargs: Any) -> list[Any]:
    """
    A fieldgetter that fetches the version from the first Kubernetes object
    that matches the criteria.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                version_regex (str): The regular expression to use to extract the version
                path (str): The path to get the string to extract the version from
        Returns:
            ([str]): The list of version fields
    """
    version_regex: str = deep_get(kwargs, DictPath("version_regex"), "")
    kind: str = deep_get(kwargs, DictPath("kind"), "")
    api_family: str = deep_get(kwargs, DictPath("api_family"), "")
    path: str = deep_get(kwargs, DictPath("path"), "")
    namespace: str = deep_get(kwargs, DictPath("namespace"), "")
    label_selector: dict[str, Any] = deep_get(kwargs, DictPath("label_selector"), {})
    version: list[str] = []

    kh = deep_get(kwargs, DictPath("kubernetes_helper"))

    if not kh:
        return []

    vlist, _status = \
        kh.get_list_by_kind_namespace((kind, api_family),
                                      namespace,
                                      label_selector=make_label_selector(label_selector))

    for obj in vlist:
        value = deep_get(obj, DictPath(path), "")
        if (tmp := re.match(version_regex, value)) is not None:
            version += list(tmp.groups())
            break
    return ["".join(version)]
