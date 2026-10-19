# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given an incomplete kind (no API-group) guess its full (kind, API-group) tuple.
"""

from typing import cast

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit import kubernetes_resources


# pylint: disable-next=too-many-branches,too-many-return-statements
def guess_kind(kind: str | tuple[str, str]) -> tuple[str, str]:
    """
    Given a Kind without API-group, or (API-name, API-group)
    return the (Kind, API-group) tuple.

        Parameters:
            kind (str):
                kind (str): The Kubernetes kind
            kind ((str, str)):
                kind (str): The API-name
                api_group (str): The API-group
        Returns:
            (str, str):
                (str): The Kubernetes kind
                (str): The API-group
        Raises:
            NameError: No matching API could be found
            TypeError: kind is not a str or (str, str) tuple
    """
    if not isinstance(kind, (str, tuple)):
        raise TypeError(f"kind must be str or (str, str); got {kind!r}")
    if isinstance(kind, tuple) \
            and not (len(kind) == 2 and isinstance(kind[0], str) and isinstance(kind[1], str)):
        raise TypeError(f"kind must be str or (str, str); got {kind!r}")

    if isinstance(kind, str):
        if "." in kind:
            kind = cast(tuple[str, str], tuple(kind.split(".", maxsplit=1)[0:2]))
        else:
            kind = (kind, "")

    # If the API-group is "core", replace it with the empty string.
    if kind[1] == "core":
        kind = (kind[0], "")

    # If we already have a tuple, do not guess
    if kind in kubernetes_resources.kubernetes_resources \
            or kind in kubernetes_resources.unknown_kubernetes_resources:
        return cast(tuple, kind)

    if kind[0].startswith("__"):
        return cast(tuple, kind)

    guess = None

    # If we have a tuple that didn't match we can try
    # matching it against the api + api_group instead.
    # To do that we need to scan.
    for resource_kind, resource_data in kubernetes_resources.kubernetes_resources.items():
        api_name = deep_get(resource_data, DictPath("api"))
        resource_name = resource_kind[0].lower()
        resource_family = resource_kind[1].lower()
        kind_name = kind[0].lower()
        kind_family = kind[1].lower()
        if resource_name == kind_name and resource_family == kind_family:
            return resource_kind
        if (api_name, resource_family) == kind:
            return resource_kind
        if resource_name == kind_name and kind_family == "":
            # Special-case the built-in APIs
            if resource_family in ("admissionregistration.k8s.io",
                                   "apiextensions.k8s.io",
                                   "apps",
                                   "autoscaling",
                                   "batch",
                                   "certificates.k8s.io",
                                   "coordination.k8s.io",
                                   "discovery.k8s.io",
                                   "events.k8s.io",
                                   "flowcontrol.apiserver.k8s.io",
                                   "internal.apiserver.k8s.io",
                                   "metacontroller.k8s.io"):
                return resource_kind

            if guess is None:
                guess = resource_kind
            else:
                guess = None
                break

    if guess is not None:
        return guess

    errmsg: list[list[tuple[str, str]]] = [
        [("Unknown kind (", "default"),
         (f"{kind[0]}.{kind[1]}", "argument"),
         (") encountered; adding to temporary dict.", "default")],
    ]
    unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
    cmtlog.log(LogLevel.INFO, msg=unformatted_msg, messages=formatted_msg)
    kubernetes_resources.unknown_kubernetes_resources[kind] = {}

    return kind
