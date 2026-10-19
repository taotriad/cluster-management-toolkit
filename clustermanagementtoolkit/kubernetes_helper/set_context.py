# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Change the Kubernetes-context.
"""

from clustermanagementtoolkit.cmtpaths import KUBE_CONFIG_FILE

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cmtio_yaml import secure_write_yaml

from clustermanagementtoolkit.kubernetes_helper.__read_kubeconfig import __read_kubeconfig


def set_context(config_path: FilePath | None = None, name: str = "") -> str:
    """
    Change context.

        Parameters:
            config_path (FilePath): The path to the kubeconfig file
            name (str): The context to change to
        Returns:
            context (str): The name of the new current-context, or empty on failure
    """
    # We need a context name
    if not name:
        return ""

    if config_path is None:
        # Read kubeconfig
        config_path = KUBE_CONFIG_FILE

    if not (kubeconfig := __read_kubeconfig(config_path)):
        return ""

    new_context = ""

    # Find out whether the new context exists
    for context in deep_get(kubeconfig, DictPath("contexts"), []):
        if deep_get(context, DictPath("name"), "") == name:
            new_context = name
            break

    if new_context:
        kubeconfig["current-context"] = new_context
        secure_write_yaml(config_path, kubeconfig, permissions=0o600, sort_keys=False)

    return new_context
