# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper that returns all pods matching an any_of-list and an all_of-list.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_pod_set(pods: list[dict],
                any_of: list[tuple[str, str]],
                all_of: list[tuple[str, str]]) -> tuple[list[dict],
                                                        dict[tuple[str, str], list[dict]]]:
    """
    Given an any_of list (namespace, pod_prefix), and an all_of list (namespace, pod_prefix),
    returns all pod objects (if any).

        Parameters:
            pods ([pod]): A list of pod objects
            any_of ([(str, str)]): A list of (namespace, name-prefix)
                                   of which at least one must exist
            all_of ({[(str, str)]}): A list of (namespace, name-prefix) of which all must exist
        Returns:
            ([(str, str)], [(str, str)]):
                ([(str, str)]): A list of (namespace, name) for pods matching the any_of criteria
                ([(str, str)]): A dict indexed by (namespace, name-prefix)
                                of list of (namespace, name) for pods matching the all_of criteria
    """
    any_of_matches: list[dict] = []
    all_of_matches: dict[tuple[str, str], list[dict]] = {}

    for obj in pods:
        pod_name = deep_get(obj, DictPath("metadata#name"), "")
        pod_namespace = deep_get(obj, DictPath("metadata#namespace"), "")
        for match_namespace, match_name in any_of:
            # If we're instructed to match namespace and the namespace doesn't match, skip this pod
            if match_namespace and match_namespace != pod_namespace:
                continue
            # If the pod name doesn't start with the name prefix, skip this pod
            if not pod_name.startswith(match_name):
                continue
            any_of_matches.append(obj)

        for match_namespace, match_name in all_of:
            # If we're instructed to match namespace and the namespace doesn't match, skip this pod
            if match_namespace and match_namespace != pod_namespace:
                continue
            # If the pod name doesn't start with the name prefix, skip this pod
            if not pod_name.startswith(match_name):
                continue
            if (match_namespace, match_name) not in all_of_matches:
                all_of_matches[(match_namespace, match_name)] = []
            all_of_matches[(match_namespace, match_name)].append(obj)

    # If either condition fails, return empty lists
    if all_of and not all_of_matches or any_of and not any_of_matches:
        any_of_matches = []
        all_of_matches = {}

    return (any_of_matches, all_of_matches)
