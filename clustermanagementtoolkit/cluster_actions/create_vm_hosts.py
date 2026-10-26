# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Create virtual machine hosts for a Kubernetes cluster.
"""

from typing import Any

from clustermanagementtoolkit.ansible_helper import ansible_print_action_summary
from clustermanagementtoolkit.ansible_helper import populate_playbooks_from_filenames

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cluster_actions.run_playbooks import run_playbooks

# For now we require the host to have the requisite packages to create VMs installed already,
# and for the ansible user to be a member of libvirt and kvm.
vm_create_playbooks: list[FilePath] = [
    FilePath("vm_create.yaml"),
    FilePath("vm_instantiate.yaml"),
]


def create_vm_hosts(vmhost: str, hosts: list[tuple[str, str, str]], **kwargs: Any) -> int:
    """
    Create VM hosts.

        Parameters:
            vmhost (str): The name of the host that runs the VMs
            hosts ([(str, str, str)]): The hostname, IP-address, and MAC-address of the hosts
            **kwargs (dict[str, Any]): Keyword arguments
                os_image (FilePath): The local path to the OS image to use
                os_variant (str): The OS variant for the OS image
                template_name (str): The name of the template image
                extra_values (dict): Extra values to pass to Ansible
                verbose (bool): If the results are printed, should skipped tasks be printed too?
        Returns:
            (int): 0 on success, non-zero on failure
    """
    os_image: FilePath = deep_get(kwargs, DictPath("os_image"))
    os_variant: str = deep_get(kwargs, DictPath("os_variant"))
    extra_values: dict = deep_get(kwargs, DictPath("extra_values"), {})
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)

    playbooks = populate_playbooks_from_filenames(vm_create_playbooks)
    ansible_print_action_summary(playbooks)
    print()

    extra_values = {
        **extra_values,
        "base_image_name": os_image.basename(),
        "os_variant": os_variant,
        "instances": hosts,
    }

    # Now prepare the VM-template
    retval = run_playbooks(playbooks=playbooks, hosts=[vmhost],
                           extra_values=extra_values, verbose=verbose)

    # OK, we now have VMs running that can be joined as nodes. Our job here is done.
    return retval
