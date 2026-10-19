# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of Role/ClusterRole policy rules.
"""

import sys
from typing import Any

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=unused-argument,too-many-branches,too-many-locals
def listgetter_policy_rules(obj: dict, **kwargs: Any) -> tuple[list[dict], int]:
    """
    Listgetter for Role & ClusterRole policy rules.

        Parameters:
            obj (Dict): The object to extract Role & ClusterRole policy rule information from
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            (([dict], int)):
                ([dict]): The policy rules
                (int): The return value
    """
    vlist: list[dict] = []

    if obj is None:
        return [], 200

    # We want one entry per resource, hence a dict
    # Structure:
    # (api_group, resource): {
    #    "non_resource_urls": [],
    #    "resource_names": [],
    #    "verbs": [],
    # }
    resources: dict = {}

    for rule in deep_get(obj, DictPath("rules"), []):
        non_resource_urls = deep_get(rule, DictPath("nonResourceURLs"), [])
        resource_names = deep_get(rule, DictPath("resourceNames"), [])
        verbs = deep_get(rule, DictPath("verbs"), [])
        api_groups = deep_get(rule, DictPath("apiGroups"), [""])
        resourcelist = deep_get(rule, DictPath("resources"), [""])

        for api_group in api_groups:
            for resource in resourcelist:
                tmp = (resource, api_group)
                if tmp not in resources:
                    resources[tmp] = {
                        "non_resource_urls": {},
                        "resource_names": {},
                        "verbs": {},
                    }
                for non_resource_url in non_resource_urls:
                    resources[tmp]["non_resource_urls"][non_resource_url] = {}
                for resource_name in resource_names:
                    resources[tmp]["resource_names"][resource_name] = {}
                for verb in verbs:
                    resources[tmp]["verbs"][verb] = {}

    for item in resources.items():
        resource, data = item
        resource, api_group = resource
        non_resource_urls = list(deep_get(data, DictPath("non_resource_urls"), {}))
        resource_names = list(deep_get(data, DictPath("resource_names"), {}))
        verbs = list(deep_get(data, DictPath("verbs"), {}))
        verbs_all = "*" in verbs
        # "*" includes all other verbs
        if verbs_all:
            verbs_get = True
            verbs_list = True
            verbs_watch = True
            verbs_create = True
            verbs_update = True
            verbs_patch = True
            verbs_delete = True
            verbs_misc = ["*"]
        else:
            verbs_get = "get" in verbs
            verbs_list = "list" in verbs
            verbs_watch = "watch" in verbs
            verbs_create = "create" in verbs
            verbs_update = "update" in verbs
            verbs_patch = "patch" in verbs
            verbs_delete = "delete" in verbs
            verbs_misc = []
            for verb in verbs:
                if verb not in ("*", "get", "list", "watch",
                                "create", "update", "patch", "delete"):
                    verbs_misc.append(verb)

        vlist.append({
            "resource": resource,
            "api_group": api_group,
            "non_resource_urls": non_resource_urls,
            "resource_names": resource_names,
            "verbs": verbs,
            "verbs_all": verbs_all,
            "verbs_get": verbs_get,
            "verbs_list": verbs_list,
            "verbs_watch": verbs_watch,
            "verbs_create": verbs_create,
            "verbs_update": verbs_update,
            "verbs_patch": verbs_patch,
            "verbs_delete": verbs_delete,
            "verbs_misc": natsorted(verbs_misc)
        })

    return vlist, 200
