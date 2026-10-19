# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A fieldgetter that provides the version of the Kubernetes API-server.
"""

import copy
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def fieldgetter_api_server_version(**kwargs: Any) -> list[Any]:
    """
    A fieldgetter that provides the version of the Kubernetes API-server.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                fields ([int]): The indexes of the API-server version fields to return
        Returns:
            ([str]): The list of API-server version fields
    """
    kh = deep_get(kwargs, DictPath("kubernetes_helper"))
    fields: list[Any] = deep_get(kwargs, DictPath("fields"), [])

    field_list = []

    if not kh:
        return []

    result = kh.get_api_server_version()
    if not fields:
        field_list = list(copy.deepcopy(result))
    else:
        for i, field in enumerate(result):
            if i in fields:
                field_list.append(field)
    return field_list
