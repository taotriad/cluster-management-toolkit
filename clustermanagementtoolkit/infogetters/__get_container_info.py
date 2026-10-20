# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper to get information from containers.
"""

from typing import Literal

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper import get_image_version


def __get_container_info(obj: dict, container_type: Literal["Container", "InitContainer"],
                         spec_path: DictPath, status_path: DictPath) -> dict:
    containers: dict = {}

    for container in deep_get(obj, spec_path, []):
        container_name = deep_get(container, DictPath("name"))
        container_image = deep_get(container, DictPath("image"))
        image_version = get_image_version(container_image)

        # To get the image ID we need to cross-reference container_image
        # against status#{status_path}->image"
        image_id = None
        for item in deep_get(obj, status_path, []):
            if deep_get(item, DictPath("name"), "") == container_name:
                image_id = deep_get(item, DictPath("imageID"))
        # This (most likely) means that the pod has not managed to instantiate a container
        if image_id is None:
            image_id = "<unknown>"
        key = (container_name, container_type, image_version, image_id)

        # If this container is in the dict already, just add a pod reference
        # This is unlikely to ever happen (this would mean that the same pod
        # uses the same image multiple times which seems unlikely), but better safe than sorry
        if key not in containers:
            containers[key] = {}
            containers[key]["pod_references"] = []
            containers[key]["instances"] = 0

        containers[key]["pod_references"].append(obj)
        containers[key]["instances"] += 1

    return containers
