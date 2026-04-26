#! /usr/bin/env python3
# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Get data for fields in a list; typically used to populate _extra_data
"""

import copy
import re
from typing import Any
from collections.abc import Callable

from clustermanagementtoolkit.cmtio import execute_command_with_response, secure_which

from clustermanagementtoolkit.cmtlib import make_label_selector

from clustermanagementtoolkit.cmtpaths import HOMEDIR

from clustermanagementtoolkit.cmttypes import deep_get, DictPath, FilePath
from clustermanagementtoolkit.cmttypes import SecurityPolicy


def fieldgetter_executable_version(**kwargs: Any) -> list[str]:
    """
    A fieldgetter that provides the version from an executable.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                executable (str): The executable to get the version for
                args ([str]): The arguments to pass to the executable
                version_regex (str): The regular expression to use to extract the version
        Returns:
            [str]: The version tuple
    """
    executables: FilePath | list[FilePath] = deep_get(kwargs, DictPath("executable"), "")
    args: list[str] = deep_get(kwargs, DictPath("args"), [])
    version_regex: str = deep_get(kwargs, DictPath("version_regex"), '')

    security_policy = SecurityPolicy.ALLOWLIST_RELAXED
    fallback_allowlist = ["/bin", "/sbin", "/usr/bin", "/usr/sbin",
                          "/usr/local/bin", "/usr/local/sbin", f"{HOMEDIR}/bin"]

    if isinstance(executables, (str, FilePath)):
        executables = [FilePath(executables)]

    version: list[str] = []

    for executable in executables:
        try:
            executable_path = secure_which(FilePath(executable),
                                           fallback_allowlist=fallback_allowlist,
                                           security_policy=security_policy)
        except FileNotFoundError:
            continue

        if not executable_path:
            continue

        try:
            result, _retval = execute_command_with_response([executable_path] + args)
        except OSError as e:
            if str(e).startswith("[Errno 26] Text file busy"):
                continue

        if result:
            for line in result.splitlines():
                if (tmp := re.match(version_regex, line)) is not None:
                    for field in tmp.groups():
                        version.append(field)
                    break

    return ["".join(version)]


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
            for field in tmp.groups():
                version.append(field)
            break
    return ["".join(version)]


# Fieldgetters acceptable for direct use in view files
fieldgetter_allowlist: dict[str, Callable] = {
    "fieldgetter_api_server_version": fieldgetter_api_server_version,
    "fieldgetter_executable_version": fieldgetter_executable_version,
    "fieldgetter_kubernetes_object_version": fieldgetter_kubernetes_object_version,
}
