# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of available Kubernetes contexts.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper.__read_kubeconfig import __read_kubeconfig


def list_contexts(config_path: FilePath | None = None) \
        -> list[tuple[bool, str, str, str, str, str]]:
    """
    Given the path to a kubeconfig file, returns the available contexts.

        Parameters:
            config_path (FilePath): The path to the kubeconfig file
        Returns:
            contexts (list[(current, name, cluster, authinfo, namespace)]):
                current (bool): Is this the current context?
                name (str): The name of the context
                cluster (str): The name of the cluster
                authinfo (str): The name of the user
                namespace (str): The name of the namespace
                server (str): The API-server of the cluster
    """
    contexts = []

    if not (kubeconfig := __read_kubeconfig(config_path)):
        return []

    current_context = deep_get(kubeconfig, DictPath("current-context"), "")

    for context in deep_get(kubeconfig, DictPath("contexts"), []):
        name = deep_get(context, DictPath("name"))
        # In this case the parentheses really help legibility
        # pylint: disable-next=superfluous-parens
        current = (name == current_context)
        namespace = deep_get(context, DictPath("namespace"), "default")
        authinfo = deep_get(context, DictPath("context#user"))
        cluster = deep_get(context, DictPath("context#cluster"))
        server = ""
        for cluster_data in deep_get(kubeconfig, DictPath("clusters"), []):
            if cluster == deep_get(cluster_data, DictPath("name")):
                server = deep_get(cluster_data, DictPath("cluster#server"))
        contexts.append((current, name, cluster, authinfo, namespace, server))
    return contexts
