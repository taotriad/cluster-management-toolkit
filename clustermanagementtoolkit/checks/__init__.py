# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
This module provides functionality for troubleshooting malfunctioning clusters,
auditing configuration and cluster for potential security issues,
pre-flight checks to run before preparing or installing new systems,
and pre-upgrade checks to run before upgrading a system to a newer version.

This module requires init_ansithemeprint() to have been executed first.
"""

# pylint: disable=line-too-long
from clustermanagementtoolkit.checks.check_ansible_dir_permissions import check_ansible_dir_permissions  # noqa: E501
from clustermanagementtoolkit.checks.check_client_server_version_match import check_client_server_version_match  # noqa: E501
from clustermanagementtoolkit.checks.check_control_plane import check_control_plane
from clustermanagementtoolkit.checks.check_disable_strict_host_key_checking import check_disable_strict_host_key_checking  # noqa: E501
from clustermanagementtoolkit.checks.check_file_permissions import check_file_permissions
from clustermanagementtoolkit.checks.check_insecure_kube_config_options import check_insecure_kube_config_options  # noqa: E501
from clustermanagementtoolkit.checks.check_known_hosts_hashing import check_known_hosts_hashing
from clustermanagementtoolkit.checks.check_kubelet_and_kube_proxy_versions import check_kubelet_and_kube_proxy_versions  # noqa: E501
from clustermanagementtoolkit.checks.check_netrc_permissions import check_netrc_permissions
from clustermanagementtoolkit.checks.check_running_pods import check_running_pods
from clustermanagementtoolkit.checks.check_sudo_configuration import check_sudo_configuration
# pylint: enable=line-too-long

__all__ = [
    "check_ansible_dir_permissions",
    "check_client_server_version_match",
    "check_control_plane",
    "check_disable_strict_host_key_checking",
    "check_file_permissions",
    "check_insecure_kube_config_options",
    "check_known_hosts_hashing",
    "check_kubelet_and_kube_proxy_versions",
    "check_netrc_permissions",
    "check_running_pods",
    "check_sudo_configuration",
]
