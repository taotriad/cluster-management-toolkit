# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Setup Kubernetes nodes.
"""

from typing import Any

from clustermanagementtoolkit.ansible_helper import ansible_print_action_summary
from clustermanagementtoolkit.ansible_helper import populate_playbooks_from_filenames

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.cluster_actions.get_api_server_package_version import get_api_server_package_version  # noqa: E501
from clustermanagementtoolkit.cluster_actions.run_playbooks import run_playbooks

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit import kubernetes_helper

setup_playbooks: list[FilePath] = [
    FilePath("add_kubernetes_repo.yaml"),
    FilePath("kubeadm_setup_node.yaml"),
]


def setup_nodes(hosts: list[str], **kwargs: Any) -> int:
    """
    Given a list of hostnames do every bit of setup except joining the nodes to the cluster.

        Parameters:
            hosts ([str]): A list of hosts to setup as nodes
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                k8s_distro (str): The Kubernetes distribution
                extra_values (dict): Extra values to pass to Ansible
                verbose (bool): If the results are printed, should skipped tasks be printed too?
        Returns:
            (int): 0 on success, non-zero on failure
    """
    kh: kubernetes_helper.KubernetesHelper = deep_get(kwargs, DictPath("kubernetes_helper"))
    k8s_distro: str = deep_get(kwargs, DictPath("k8s_distro"), "kubeadm")
    extra_values: dict = deep_get(kwargs, DictPath("extra_values"), {})
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)
    cri: str = deep_get(kwargs, DictPath("cri"))

    # Add the CRI to the setup playbooks for the control plane;
    # the list is short enough that doing prepend isn't a performance issue.
    setup_playbooks_with_cri = []
    if cri == "containerd":
        setup_playbooks_with_cri += [FilePath("setup_containerd.yaml")]
    elif cri == "cri-o":
        setup_playbooks_with_cri += [FilePath("setup_cri-o.yaml")]
    setup_playbooks_with_cri += setup_playbooks

    playbooks = populate_playbooks_from_filenames(setup_playbooks_with_cri)
    ansible_print_action_summary(playbooks)
    print()

    version, _version_major, _version_minor = \
        get_api_server_package_version(kubernetes_helper=kh, k8s_distro=k8s_distro)

    extra_values = {
        **extra_values,
        "control_plane_k8s_version": version,
    }

    # Now setup the hosts
    return run_playbooks(playbooks=playbooks, hosts=hosts,
                         extra_values=extra_values, verbose=verbose)
