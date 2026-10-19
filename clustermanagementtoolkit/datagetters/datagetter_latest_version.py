# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the latest available API-version for an API.
"""

import re
from typing import Any

from clustermanagementtoolkit.kubernetes_helper import kind_tuple_to_name, guess_kind

from clustermanagementtoolkit.cmttypes import deep_get, DictPath
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def datagetter_latest_version(obj: dict[str, Any],
                              **kwargs: Any) -> tuple[tuple[str, str, str], dict]:
    """
    A datagetter that returns the latest available API for kind as passed in path.

        Parameters:
            obj (dict): The object to get the old API information from
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
                path ([kind_path, api_family_path, old_version_path)]:
                                         Paths to Kind, API-family, and the old version of the API
                default: Unused?
        Returns:
            (str, str, str, dict):
                (str): new API-group (since it might change)
                (str): The latest version of the API, or old_version if no newer version available
                (str): If the API is deprecated, the deprecation message (if one available),
                       or a default message (if not)
                (dict): An empty dict
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    path = deep_get(kwargs, DictPath("path"))
    default = deep_get(kwargs, DictPath("default"), ("", "", ""))

    if obj is None or path is None:
        return default, {}

    # path is paths to kind, api_family
    kind = deep_get(obj, DictPath(path[0]))
    api_family = deep_get(obj, DictPath(path[1]))
    old_version = deep_get(obj, DictPath(path[2]))
    kind = guess_kind((kind, api_family))

    latest_api = kh.get_latest_api(kind)
    if "/" in latest_api:
        group, version = latest_api.split("/")
    else:
        group = ""
        version = latest_api

    message = ""

    # Check if there's a deprecation message in the CRD
    ref = kh.get_ref_by_kind_name_namespace(("CustomResourceDefinition", "apiextensions.k8s.io"),
                                            kind_tuple_to_name(kind), "", resource_cache=kh_cache)

    if ref is not None:
        versions: dict = {}
        sorted_versions = []

        for version_entry in deep_get(ref, DictPath("spec#versions"), {}):
            version_name = deep_get(version_entry, DictPath("name"), "")
            deprecated = deep_get(version_entry, DictPath("deprecated"), False)
            deprecation_message = deep_get(version_entry, DictPath("deprecationWarning"), "")
            versions[version_name] = {
                "deprecated": deprecated,
                "deprecation_message": deprecation_message
            }
        # Kubernetes versions come in three different types
        # vX, vXbetaX, and vXalphaX
        version_regex = re.compile(r"^v(\d+)($|beta\d+|alpha\d+)$")
        tmp_versions = []
        for version in versions:
            if (re_tmp := version_regex.match(version)) is None:
                raise ValueError(f"Failed to parse version number {version}")
            try:
                major = int(re_tmp[1])
            except ValueError as e:
                raise ValueError(f"Failed to parse version number {version}") from e
            if re_tmp[2] == "":
                minor = 0
                patch = 0
            elif re_tmp[2].startswith("beta"):
                minor = -1
                try:
                    patch = int(re_tmp[2].removeprefix("beta"))
                except ValueError as e:
                    raise ValueError(f"Failed to parse version number {version}") from e
            elif re_tmp[2].startswith("alpha"):
                minor = -2
                try:
                    patch = int(re_tmp[2].removeprefix("alpha"))
                except ValueError as e:
                    raise ValueError(f"Failed to parse version number {version}") from e
            else:
                raise ValueError(f"Failed to parse version number {version}")
            tmp_versions.append((major, minor, patch))
        sorted_versions = sorted(tmp_versions, reverse=True)
        latest_major = f"v{sorted_versions[0][0]}"
        latest_minor = ""
        if sorted_versions[0][1] == 0:
            latest_minor = ""
        elif sorted_versions[0][1] == -1:
            latest_minor = f"beta{sorted_versions[0][2]}"
        elif sorted_versions[0][1] == -2:
            latest_minor = f"alpha{sorted_versions[0][2]}"
        latest_version = f"{latest_major}{latest_minor}"

        if deep_get(versions, DictPath(f"{latest_version}#deprecated"), False):
            message = deep_get(versions, DictPath(f"{latest_version}#deprecation_message"), "")
            message = f"({message})"

    else:
        latest_version = version

    if old_version == latest_version and not message:
        message = "(No newer version available; the API might be deprecated)"

    return (group, latest_version, message), {}
