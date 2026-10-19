# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of containers + their status.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper.get_image_version import get_image_version


def get_containers(containers: list[dict[str, Any]],
                   container_statuses: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """
    Given a list of containers and a list of container statuses,
    create a joined list with both pieces of information.

        Parameters:
            containers ([dict]): The list of container info
            container_statuses ([dict]): The list of container statuses
        Returns:
            ([(str, str)]): The list of container info
    """
    container_dict = {}
    container_list = []

    for container in containers:
        container_name = deep_get(container, DictPath("name"))
        container_image = deep_get(container, DictPath("image"))
        image_version = get_image_version(container_image)
        container_dict[container_name] = image_version

    for container in container_statuses:
        container_name = deep_get(container, DictPath("name"))
        container_image = deep_get(container, DictPath("image"))
        if container_dict[container_name] == "<undefined>":
            image_version = get_image_version(container_image, "<undefined>")
            container_list.append((container_name, image_version))
        else:
            container_list.append((container_name, container_dict[container_name]))

    return container_list
