# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Itemgetters that are used to populate data for the windowwidget.
"""

from collections.abc import Callable

from clustermanagementtoolkit.itemgetters.get_affinity import get_affinity
from clustermanagementtoolkit.itemgetters.get_conditions import get_conditions
from clustermanagementtoolkit.itemgetters.get_dict_list import get_dict_list
from clustermanagementtoolkit.itemgetters.get_events import get_events
from clustermanagementtoolkit.itemgetters.get_image_list import get_image_list
from clustermanagementtoolkit.itemgetters.get_key_value import get_key_value
from clustermanagementtoolkit.itemgetters.get_kubernetes_objects import get_kubernetes_objects
from clustermanagementtoolkit.itemgetters.get_list_as_list import get_list_as_list
from clustermanagementtoolkit.itemgetters.get_list_as_string import get_list_as_string
from clustermanagementtoolkit.itemgetters.get_list_fields import get_list_fields
from clustermanagementtoolkit.itemgetters.get_package_version_list import get_package_version_list
from clustermanagementtoolkit.itemgetters.get_pod_configmaps import get_pod_configmaps
from clustermanagementtoolkit.itemgetters.get_prepopulated_list import get_prepopulated_list
from clustermanagementtoolkit.itemgetters.get_resource_list import get_resource_list
from clustermanagementtoolkit.itemgetters.get_security_context import get_security_context
from clustermanagementtoolkit.itemgetters.get_selector_list import get_selector_list
from clustermanagementtoolkit.itemgetters.get_strings_from_string import get_strings_from_string
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.itemgetters.get_svc_port_target_endpoints import get_svc_port_target_endpoints  # noqa: E501
from clustermanagementtoolkit.itemgetters.get_tolerations import get_tolerations
from clustermanagementtoolkit.itemgetters.get_volume_properties import get_volume_properties

# Itemgetters acceptable for direct use in view files
itemgetter_allowlist: dict[str, Callable] = {
    "get_conditions": get_conditions,
    "get_kubernetes_objects": get_kubernetes_objects,
    "get_events": get_events,
    "get_image_list": get_image_list,
    "get_key_value": get_key_value,
    "get_list_as_list": get_list_as_list,
    "get_list_as_string": get_list_as_string,
    "get_dict_list": get_dict_list,
    "get_selector_list": get_selector_list,
    "get_list_fields": get_list_fields,
    "get_package_version_list": get_package_version_list,
    "get_affinity": get_affinity,
    "get_pod_configmaps": get_pod_configmaps,
    "get_prepopulated_list": get_prepopulated_list,
    "get_tolerations": get_tolerations,
    "get_resource_list": get_resource_list,
    "get_strings_from_string": get_strings_from_string,
    "get_security_context": get_security_context,
    "get_svc_port_target_endpoints": get_svc_port_target_endpoints,
    "get_volume_properties": get_volume_properties,
}
