# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns a list containing the security context.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


security_context_values: dict[str, list[DictPath]] = {
    "Run as User": [
        DictPath("securityContext#runAsUser"),
        DictPath("spec#securityContext#runAsUser"),
        DictPath("spec#template#spec#securityContext#runAsUser")],
    "Run as non-Root": [
        DictPath("securityContext#runAsNonRoot"),
        DictPath("spec#securityContext#runAsNonRoot"),
        DictPath("spec#template#spec#securityContext#runAsNonRoot")],
    "Run as Group": [
        DictPath("securityContext#runAsGroup"),
        DictPath("spec#securityContext#runAsGroup"),
        DictPath("spec#template#spec#securityContext#runAsGroup")],
    "FS Group": [
        DictPath("securityContext#fsGroup"),
        DictPath("spec#securityContext#fsGroup"),
        DictPath("spec#template#spec#securityContext#fsGroup")],
    "FS Group-change Policy": [
        DictPath("securityContext#fsGroupChangePolicy"),
        DictPath("spec#securityContext#fsGroupChangePolicy"),
        DictPath("spec#template#spec#securityContext#fsGroupChangePolicy")],
    "Allow Privilege Escalation": [
        DictPath("securityContext#allowPrivilegeEscalation"),
        DictPath("spec#securityContext#allowPrivilegeEscalation"),
        DictPath("spec#template#spec#securityContext#allowPrivilegeEscalation")],
    "Capabilities": [
        DictPath("securityContext#capabilities"),
        DictPath("spec#securityContext#capabilities"),
        DictPath("spec#template#spec#securityContext#capabilities")],
    "Privileged": [
        DictPath("securityContext#privileged"),
        DictPath("spec#securityContext#privileged"),
        DictPath("spec#template#spec#securityContext#privileged")],
    "Proc Mount": [
        DictPath("securityContext#procMount"),
        DictPath("spec#securityContext#procMount"),
        DictPath("spec#template#spec#securityContext#procMount")],
    "Read-only Root Filesystem": [
        DictPath("securityContext#readOnlyRootFilesystem"),
        DictPath("spec#securityContext#readOnlyRootFilesystem"),
        DictPath("spec#template#spec#securityContext#readOnlyRootFilesystem")],
    "SELinux Options": [
        DictPath("securityContext#seLinuxOptions"),
        DictPath("spec#securityContext#seLinuxOptions"),
        DictPath("spec#template#spec#securityContext#seLinuxOptions")],
    "Seccomp Profile": [
        DictPath("securityContext#seccompProfile"),
        DictPath("spec#securityContext#seccompProfile"),
        DictPath("spec#template#spec#securityContext#seccompProfile")],
    "Windows Options": [
        DictPath("securityContext#windowsOptions"),
        DictPath("spec#securityContext#windowsOptions"),
        DictPath("spec#template#spec#securityContext#windowsOptions")],
}


def get_security_context(obj: dict, **kwargs: Any) -> list[tuple[str, str]]:
    """
    Get security context information.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([(str, str)]): A list of security context information
    """
    security_policies: list[tuple[str, str]] = []
    security_context_path: str = deep_get(kwargs, DictPath("path"), "")

    for name, paths in security_context_values.items():
        for path in paths:
            if security_context_path:
                path = DictPath(f"{security_context_path}#{path}")
            if (policy := deep_get(obj, path)) is not None:
                security_policies.append((name, str(policy)))
                break

    return security_policies
