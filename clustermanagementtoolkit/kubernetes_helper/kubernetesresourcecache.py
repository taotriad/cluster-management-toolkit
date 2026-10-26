# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A cache for Kubernetes resources.
"""

import copy
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


class KubernetesResourceCache:
    """
    A class for caching Kubernetes resources.
    """
    updated = False

    def __init__(self) -> None:
        """
        Initialize the resource cache.
        """
        self.resource_cache: dict = {}

    def update_resource(self, kind: tuple[str, str], resource: dict) -> None:
        """
        Add or update the cache entry for a resource.

            Parameters:
                kind ((str, str)): The kind tuple for the resource
                resource (dict): The resource data
        """
        if kind not in self.resource_cache:
            self.resource_cache[kind] = {
                "resource_version": None,
                "resources": {},
            }

        # Some resources lack a UID (notably metrics);
        # let's not cache those.
        if not (uid := deep_get(resource, DictPath("metadata#uid"), "")):
            return

        resource_version = deep_get(resource, DictPath("metadata#resourceVersion"))
        if resource_version is None:
            raise ProgrammingError("KubernetesResourceCache.update_resource(): "
                                   "Attempt to add a resource with empty or None "
                                   "resourceVersion was made")
        if not resource_version:
            resource_version = "0"
        if uid not in self.resource_cache[kind]:
            self.resource_cache[kind]["resource_version"] = int(resource_version)
            self.resource_cache[kind]["resources"][uid] = copy.deepcopy(resource)
            self.updated = True
        elif deep_get(self.resource_cache[kind],
                      DictPath("uid#metadata#resourceVersion"), "0") < int(resource_version):
            # Only update if the new version has a resource version
            # strictly higher than the old version
            self.resource_cache[kind]["resource_version"] = int(resource_version)
            self.resource_cache[kind].pop(uid, None)
            self.resource_cache[kind]["resources"][uid] = copy.deepcopy(resource)
            self.updated = True

    def update_resources(self, kind: tuple[str, str], resources: list[dict]) -> None:
        """
        Add or update the cache entries for a resource kind.

            Parameters:
                kind ((str, str)): The kind tuple for the resources
                resources (dict): The resource data
        """
        if resources is None or not resources:
            raise ProgrammingError("KubernetesResourceCache.update_resources(): "
                                   "resources is empty or None")

        for resource in resources:
            self.update_resource(kind, resource=resource)

    def get_resources(self, kind: tuple[str, str], namespace: str = "",
                      label_selector: str = "", field_selector: str = "") -> list[dict[str, Any]]:
        """
        Return a list with all resources of the specified kind.

            Parameters:
                kind ((str, str)): The kind tuple for the resources
                namespace (str): The namespace of the resource (None to return all namespaces)
                label_selector (str): A label selector
                field_selector (str): A field selector
            Returns:
                ([dict]): The list of cached resources of the specified kind
        """
        if kind not in self.resource_cache:
            return []

        if namespace is not None and namespace or label_selector or field_selector:
            vlist = []
            field_selector_dict = {}
            for selector in field_selector.split(","):
                if not selector:
                    continue
                key, value = selector.split("=")
                key = key.replace(".", "#")
                field_selector_dict[key] = value
            label_selector_dict = {}
            for selector in label_selector.split(","):
                if not selector:
                    continue
                key, value = selector.split("=")
                key = key.replace(".", "#")
                label_selector_dict[f"metadata#labels#{key}"] = value

            for resource in deep_get(self.resource_cache[kind], DictPath("resources"), {}).values():
                if deep_get(resource, DictPath("metadata#namespace"), "") != namespace:
                    continue
                for key, value in field_selector_dict.items():
                    if deep_get(resource, DictPath(key), "") != value:
                        continue
                for key, value in label_selector_dict.items():
                    if deep_get(resource, DictPath(key), "") != value:
                        continue
                vlist.append(resource)
            return vlist
        return [resource for uid, resource in deep_get(self.resource_cache[kind],
                                                       DictPath("resources"), {}).items()]

    def index(self) -> list[str]:
        """
        Return a list of all cached kinds.

            Returns:
                ([(str, str]): A list of kind tuples of all cached kinds
        """
        if self.resource_cache is None:
            return []
        return list(self.resource_cache)

    def __len__(self) -> int:
        """
        Return the number of cached kinds.

            Returns:
                (int): The number of cached kinds
        """
        if self.resource_cache is None:
            return 0
        return len(self.resource_cache)

    def len(self, kind: tuple[str, str]) -> int:
        """
        Return the number of resources of the specified kind.

            Parameters:
                kind ((str, str)): The kind tuple for the resources
            Returns:
                (int): The number of cached resources of the specified kind
        """
        if self.resource_cache is None or kind not in self.resource_cache:
            return 0

        return len(deep_get(self.resource_cache[kind], DictPath("resources"), {}))
