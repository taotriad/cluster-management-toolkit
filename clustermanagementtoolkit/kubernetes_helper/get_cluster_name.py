# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the name of the cluster.
"""

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmtpaths import KUBE_CONFIG_FILE


def get_cluster_name() -> str | None:
    """
    Return the name of the cluster.

        Returns:
            (str): The name of the cluster
    """
    try:
        d1 = dict(secure_read_yaml(KUBE_CONFIG_FILE))
    except (FileNotFoundError, TypeError):
        return None

    current_context = d1.get("current-context", None)
    if current_context is None:
        return None

    cluster_name = None

    for context in d1.get("contexts", []):
        if context.get("name", "") == current_context:
            cluster_name = context["context"].get("cluster", None)
            break

    return cluster_name
