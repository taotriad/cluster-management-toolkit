# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Join nodes to the Kubernetes cluster.
"""

import errno
import sys
from typing import Any

from clustermanagementtoolkit.ansible_helper import ansible_print_action_summary
from clustermanagementtoolkit.ansible_helper import populate_playbooks_from_filenames

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.cluster_actions.get_api_server_package_version import get_api_server_package_version  # noqa: E501
from clustermanagementtoolkit.cluster_actions.run_playbooks import run_playbooks

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper import KubernetesHelper

cri_data: dict[str, dict[str, str]] = {
    "containerd": {
        "socket": "unix:///run/containerd/containerd.sock",
    },
    "cri-o": {
        "socket": "unix:///run/crio/crio.sock",
    },
}

join_playbooks: list[FilePath] = [
    FilePath("kubeadm_join_node.yaml"),
]


# pylint: disable-next=too-many-locals
def join_nodes(hosts: list[str], **kwargs: Any) -> int:
    """
    Given a list of hostnames join them as worker nodes to the cluster.

        Parameters:
            hosts ([str]): A list of hosts to join to the cluster
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                k8s_distro (str): The Kubernetes distribution
                extra_values (dict): Extra values to pass to Ansible
                verbose (bool): If the results are printed, should skipped tasks be printed too?
        Returns:
            (int): 0 on success, non-zero on failure
    """
    kh: KubernetesHelper = deep_get(kwargs, DictPath("kubernetes_helper"))
    k8s_distro: str = deep_get(kwargs, DictPath("k8s_distro"), "kubeadm")
    cri: str = deep_get(kwargs, DictPath("cri"))
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)
    extra_values: dict = deep_get(kwargs, DictPath("extra_values"), {})

    cri_socket: str = deep_get(cri_data[cri], DictPath("socket"))

    join_token = None
    ca_cert_hash = None

    version, version_major, version_minor = \
        get_api_server_package_version(kubernetes_helper=kh, k8s_distro=k8s_distro)
    if k8s_distro == "kubeadm":
        join_token = kh.get_join_token()
        ca_cert_hash = kh.get_ca_cert_hash()

    control_plane_ip, control_plane_port, control_plane_path = kh.get_control_plane_address()
    if control_plane_ip is None:
        ansithemeprint([ANSIThemeStr("\nAborting", "error"),
                        ANSIThemeStr(": Could not get the IP-address for the control plane.",
                                     "default")], stderr=True)
        sys.exit(errno.ENOENT)

    playbooks = populate_playbooks_from_filenames(join_playbooks)
    ansible_print_action_summary(playbooks)
    print()

    # Currently we only support kubeadm
    if k8s_distro == "kubeadm":
        if int(version_minor) < 31:
            join_configuration_api_version = "kubeadm.k8s.io/v1beta3"
        else:
            join_configuration_api_version = "kubeadm.k8s.io/v1beta4"

        extra_values = {
            **extra_values,
            "control_plane_ip": control_plane_ip,
            "control_plane_port": control_plane_port,
            "control_plane_path": control_plane_path,
            "join_token": join_token,
            "ca_cert_hash": ca_cert_hash,
            "configuration_path": "templates/config/nodeconfig.yaml.j2",
            "control_plane_k8s_version": version,
            "cri_socket": cri_socket,
            "kubernetes_major_minor_version": f"{version_major}.{version_minor}",
            "join_configuration_api_version": join_configuration_api_version,
        }

    # Now join the hosts
    return run_playbooks(playbooks=playbooks, hosts=hosts,
                         extra_values=extra_values, verbose=verbose)
