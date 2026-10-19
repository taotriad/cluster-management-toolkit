# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A datagetter to return information about CMT's support for an API.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.kubernetes_helper import guess_kind


def datagetter_api_support(obj: dict[str, Any], **kwargs: Any) -> tuple[list[str], dict]:
    """
    A datagetter that returns the level of support that CMT provides for an API;
    can be one of:
    * Known (CMT has an API definition)
    * List (CMT has a list view)
    * Info (CMT has an info view)

        Parameters:
            obj (dict): The object to get the API-name from
            kwargs (dict):
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                default (Any): Data to return if the object is None
        Returns:
            ([str], dict):
                ([str]): A list with zero or more of "Known", "List", "Info"
                (dict): An empty dict
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")

    default = deep_get(kwargs, DictPath("default"))

    if obj is None:
        return default, {}

    kind = deep_get(obj, DictPath("spec#names#kind"), "")
    api_family = deep_get(obj, DictPath("spec#group"), "")

    available_apis, _status, _modified = kh.get_available_kinds()

    available_views = []

    kind = guess_kind((kind, api_family))
    available_views.append("Known")

    # If kind is not in available_apis it's an unknown kind
    if kind not in available_apis:
        return [], {}

    if deep_get(available_apis[kind], DictPath("list"), False):
        available_views.append("List")
    if deep_get(available_apis[kind], DictPath("info"), False):
        available_views.append("Info")

    if not available_views:
        available_views = default

    return available_views, {}
