# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Create a template VM image to use when instantiating virtualised Kubernetes nodes.
"""

from typing import Any

from clustermanagementtoolkit.ansible_helper import ansible_print_action_summary
from clustermanagementtoolkit.ansible_helper import populate_playbooks_from_filenames

from clustermanagementtoolkit.cluster_actions.run_playbooks import run_playbooks
from clustermanagementtoolkit.cluster_actions.setup_nodes import setup_nodes

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper import KubernetesHelper

# For now we require the host to have the requisite packages to create VMs installed already,
# and for the ansible user to be a member of libvirt and kvm.
vm_create_template_playbooks: list[FilePath] = [
    FilePath("vm_template_create.yaml"),
    FilePath("vm_template_instantiate.yaml"),
]

# Commit template changes to the backing image.
vm_commit_template_playbooks: list[FilePath] = [
    FilePath("vm_template_commit.yaml"),
]

# While destroy might sound extremely destructive, the VM-image remains untouched.
# destroy refers to the virtual machine, which we don't want running, since we will need
# use it as base image for new images.
vm_destroy_template_playbooks: list[FilePath] = [
    FilePath("vm_destroy.yaml"),
]


def prepare_vm_template(vmhost: str, hosts: list[tuple[str, str, str]], **kwargs: Any) -> int:
    """
    Create a template VM image to use when instantiating virtualised nodes.

        Parameters:
            vmhost (str): The name of the host that runs the VMs
            hosts ([(str, str, str)]): The hostname, IP-address, and MAC-address of the template VM
            **kwargs (dict[str, Any]): Keyword arguments
                os_image (FilePath): The local path to the OS image to use
                template_name (str): The name of the template image
                template_balloon_size (str): The ballooned size of the template image
                extra_values (dict): Extra values to pass to Ansible
                verbose (bool): If the results are printed, should skipped tasks be printed too?
        Returns:
            (int): 0 on success, non-zero on failure
    """
    kh: KubernetesHelper = deep_get(kwargs, DictPath("kubernetes_helper"))
    os_image: FilePath = deep_get(kwargs, DictPath("os_image"))
    os_variant: str = deep_get(kwargs, DictPath("os_variant"))
    template_name: str = deep_get(kwargs, DictPath("template_name"))
    template_balloon_size: str = deep_get(kwargs, DictPath("template_balloon_size"))
    extra_values: dict[str, Any] = deep_get(kwargs, DictPath("extra_values"), {})
    cri: str = deep_get(kwargs, DictPath("cri"))
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)

    playbooks = populate_playbooks_from_filenames(vm_create_template_playbooks)
    ansible_print_action_summary(playbooks)
    print()

    extra_values = {
        **extra_values,
        "base_image": os_image,
        "base_image_name": os_image.basename(),
        "os_variant": os_variant,
        "template_name": template_name,
        "template_balloon_size": template_balloon_size,
        "instances": hosts,
    }

    # Now prepare the VM-template
    retval = run_playbooks(playbooks=playbooks, hosts=[vmhost],
                           extra_values=extra_values, verbose=verbose)

    hostnames = [hostname for hostname, _ipaddress, _macaddress in hosts]

    if not retval:
        # We've got a running VM to turn into a template;
        # we need to set it up as a Kubernetes node now.
        # Every single step except adding it to the cluster.
        retval = setup_nodes(hostnames, kubernetes_helper=kh, extra_values=extra_values, cri=cri)

    if not retval:
        # The template image is prepared and all necessary packages
        # and configuration should be installed on it. At this point we need to shut down the VM.
        playbooks = populate_playbooks_from_filenames(vm_destroy_template_playbooks)
        ansible_print_action_summary(playbooks)
        print()
        retval = run_playbooks(playbooks=playbooks, hosts=[vmhost],
                               extra_values=extra_values, verbose=verbose)

    if not retval:
        # The template image is no longer running as a VM.
        # Time to commit the changes to the backing image.
        playbooks = populate_playbooks_from_filenames(vm_commit_template_playbooks)
        ansible_print_action_summary(playbooks)
        print()
        retval = run_playbooks(playbooks=playbooks, hosts=[vmhost],
                               extra_values=extra_values, verbose=verbose)

    return retval
