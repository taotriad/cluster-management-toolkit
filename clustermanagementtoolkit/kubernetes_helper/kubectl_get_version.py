# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the versions of kubectl and the API-server.
"""

import yaml

from clustermanagementtoolkit.cmtio import execute_command_with_response
from clustermanagementtoolkit.cmtio import secure_which

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityPolicy
from clustermanagementtoolkit.cmttypes import deep_get


def kubectl_get_version(client_only: bool = False) -> tuple[int | None, int | None, str,
                                                            int | None, int | None, str]:
    """
    Get kubectl & API-server version.

        Parameters:
            client_only (bool): Only check version data for kubectl
        Returns:
            (int, int, str, int, int, str):
                (int): Major client version
                (int): Minor client version
                (str): Client GIT version
                (int): Major API-server version
                (int): Minor API-server version
                (str): API-server GIT version
    """
    # Check kubectl version
    try:
        kubectl_path = secure_which(FilePath("/usr/bin/kubectl"),
                                    fallback_allowlist=["/etc/alternatives"],
                                    security_policy=SecurityPolicy.ALLOWLIST_RELAXED)
    except FileNotFoundError:  # pragma: no cover
        return -1, -1, "", -1, -1, ""

    args = [kubectl_path, "version", "-oyaml"]
    if client_only:
        args.append("--client=true")

    try:
        response, _retval = execute_command_with_response(args)
        version_data = yaml.safe_load(response)
    except yaml.scanner.ScannerError:  # pragma: no cover
        return -1, -1, "", -1, -1, ""

    kubectl_version = deep_get(version_data, DictPath("clientVersion"))
    server_version = deep_get(version_data, DictPath("serverVersion"))
    if kubectl_version is not None:
        kubectl_major_version = \
            int("".join(filter(str.isdigit, deep_get(kubectl_version, DictPath("major")))))
        kubectl_minor_version = \
            int("".join(filter(str.isdigit, deep_get(kubectl_version, DictPath("minor")))))
        kubectl_git_version = str(deep_get(kubectl_version, DictPath("gitVersion")))
    else:  # pragma: no cover
        kubectl_major_version = None
        kubectl_minor_version = None
        kubectl_git_version = "<unavailable>"
    if server_version is not None:
        server_major_version = \
            int("".join(filter(str.isdigit, deep_get(server_version, DictPath("major")))))
        server_minor_version = \
            int("".join(filter(str.isdigit, deep_get(server_version, DictPath("minor")))))
        server_git_version = str(deep_get(server_version, DictPath("gitVersion")))
    else:  # pragma: no cover
        server_major_version = None
        server_minor_version = None
        server_git_version = "<unavailable>"

    return kubectl_major_version, kubectl_minor_version, kubectl_git_version, \
        server_major_version, server_minor_version, server_git_version
