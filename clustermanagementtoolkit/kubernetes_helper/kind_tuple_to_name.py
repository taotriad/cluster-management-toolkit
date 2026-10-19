# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a kind-tuple, return a string representation (kind.apigroup).
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit import kubernetes_resources


# Maybe this should be moved to kubernetes_resources?
def kind_tuple_to_name(kind: tuple[str, str]) -> str:
    """
    Given a kind tuple, return a string representation.

        Parameters:
            kind ((kind, api_group)): The kind tuple
                kind (str): The kind
                api_group (str): The API-group
        Returns:
            (str): The string representation of kind + API-group
    """
    name = ""

    if kind in kubernetes_resources.kubernetes_resources:
        api = deep_get(kubernetes_resources.kubernetes_resources[kind], DictPath("api"), "")
        name = f"{api}.{kind[1]}"
        name = name.rstrip(".")
    return name
