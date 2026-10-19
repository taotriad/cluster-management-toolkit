# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the resource-type for a kind.
"""

from clustermanagementtoolkit import kubernetes_resources


# Maybe we should move this to kubernetes_resources?
def resource_kind_to_rtype(resource: tuple[str, str]) -> str:
    """
    Given a kind return a resource type (basically a summary of what type is).

        Parameters:
            resource ((str, str)): The resource
        Returns:
            (str): A Resource type
    """
    return kubernetes_resources.kubernetes_resource_types.get(resource, "[unknown]")
