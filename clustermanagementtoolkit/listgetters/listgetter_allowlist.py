
# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An allowlist for listgetters.
"""

from collections.abc import Callable

# pylint: disable=line-too-long
# from clustermanagementtoolkit.listgetters.check_matchlist import check_matchlist
from clustermanagementtoolkit.listgetters.generic_listgetter import generic_listgetter
# from clustermanagementtoolkit.listgetters.get_device_model import get_device_model
from clustermanagementtoolkit.listgetters.get_info_by_last_applied_configuration import get_info_by_last_applied_configuration  # noqa: E501
from clustermanagementtoolkit.listgetters.get_ingress_rule_list import get_ingress_rule_list
from clustermanagementtoolkit.listgetters.get_metrics_list import get_metrics_list
from clustermanagementtoolkit.listgetters.get_netpol_rule_list import get_netpol_rule_list
from clustermanagementtoolkit.listgetters.get_pod_containers_list import get_pod_containers_list
from clustermanagementtoolkit.listgetters.get_pod_resource_list import get_pod_resource_list
from clustermanagementtoolkit.listgetters.listgetter_ansible_volumes import listgetter_ansible_volumes  # noqa: E501
from clustermanagementtoolkit.listgetters.listgetter_configmap_data import listgetter_configmap_data
from clustermanagementtoolkit.listgetters.listgetter_dict_list import listgetter_dict_list
from clustermanagementtoolkit.listgetters.listgetter_dir import listgetter_dir
from clustermanagementtoolkit.listgetters.listgetter_feature_gates import listgetter_feature_gates
from clustermanagementtoolkit.listgetters.listgetter_files import listgetter_files
from clustermanagementtoolkit.listgetters.listgetter_join_dicts_to_list import listgetter_join_dicts_to_list  # noqa: E501
from clustermanagementtoolkit.listgetters.listgetter_join_lists import listgetter_join_lists
from clustermanagementtoolkit.listgetters.listgetter_matchrules import listgetter_matchrules
from clustermanagementtoolkit.listgetters.listgetter_namespaced_resources import listgetter_namespaced_resources  # noqa: E501
from clustermanagementtoolkit.listgetters.listgetter_noop import listgetter_noop
from clustermanagementtoolkit.listgetters.listgetter_path import listgetter_path
from clustermanagementtoolkit.listgetters.listgetter_policy_rules import listgetter_policy_rules
# pylint: enable=line-too-long


# Listgetters acceptable for direct use in view files
listgetter_allowlist: dict[str, Callable] = {
    # Used by listview, listpad
    "generic_listgetter": generic_listgetter,
    "get_metrics_list": get_metrics_list,
    "get_pod_containers_list": get_pod_containers_list,
    "listgetter_files": listgetter_files,
    "listgetter_dir": listgetter_dir,
    # Used by listpad
    "get_ingress_rule_list": get_ingress_rule_list,
    "get_netpol_rule_list": get_netpol_rule_list,
    "get_pod_resource_list": get_pod_resource_list,
    "get_info_by_last_applied_configuration": get_info_by_last_applied_configuration,
    "listgetter_ansible_volumes": listgetter_ansible_volumes,
    "listgetter_configmap_data": listgetter_configmap_data,
    "listgetter_dict_list": listgetter_dict_list,
    "listgetter_join_dicts_to_list": listgetter_join_dicts_to_list,
    "listgetter_join_lists": listgetter_join_lists,
    "listgetter_matchrules": listgetter_matchrules,
    "listgetter_namespaced_resources": listgetter_namespaced_resources,
    "listgetter_noop": listgetter_noop,
    "listgetter_feature_gates": listgetter_feature_gates,
    "listgetter_path": listgetter_path,
    "listgetter_policy_rules": listgetter_policy_rules,
}
