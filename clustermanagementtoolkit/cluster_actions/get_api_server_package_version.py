# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the package version for the API-server.
"""

import errno
import re
import sys
from typing import Any

from clustermanagementtoolkit.ansible_helper import ansible_run_playbook_on_selection
from clustermanagementtoolkit.ansible_helper import get_playbook_path

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cluster_actions.get_control_planes import get_control_planes

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper import KubernetesHelper


# pylint: disable-next=too-many-locals
def get_api_server_package_version(**kwargs: Any) -> tuple[str, str, str]:
    """
    Get the package version for kubeadm/rke2 from the API-server.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                k8s_distro (str): The Kubernetes distribution
        Returns:
            ((str, str, str)): The package version for kubeadm/rke2
    """
    kh: KubernetesHelper = deep_get(kwargs, DictPath("kubernetes_helper"))
    k8s_distro: str = deep_get(kwargs, DictPath("k8s_distro"), "kubeadm")

    control_plane_ip, _control_plane_port, _control_plane_path = kh.get_control_plane_address()
    if control_plane_ip is None:
        ansithemeprint([ANSIThemeStr("Error", "error"),
                        ANSIThemeStr(": Failed to get control plane IP; "
                                     "aborting.", "default")], stderr=True)
        sys.exit(errno.EBADMSG)

    # If this is a kubeadm cluster we need the package version for kubeadm;
    # if it's an RKE2 cluster we try to deduce the channel from the control plane
    # Kubernetes version
    if k8s_distro == "kubeadm":
        get_version_playbook_path = get_playbook_path(FilePath("get_versions.yaml"))
        retval, ansible_results = \
            ansible_run_playbook_on_selection(get_version_playbook_path,
                                              selection=[control_plane_ip], quiet=False)
        if not ansible_results:
            ansithemeprint([ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(": Failed to get package versions from control plane "
                                         f"at {control_plane_ip} (retval: {retval}); aborting.",
                                         "default")], stderr=True)
            sys.exit(errno.ENOENT)

        tmp = []

        for result in deep_get(ansible_results, DictPath(control_plane_ip), []):
            if deep_get(result, DictPath("task"), "") == "Package versions":
                tmp = deep_get(result, DictPath("msg_lines"), [])
                break

        if not tmp:
            ansithemeprint([ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(": Failed to get package versions from control plane "
                                         f"at {control_plane_ip} (playbook returned no valid "
                                         "data); aborting.", "default")], stderr=True)
            sys.exit(errno.EBADMSG)

        version = ""
        kubeadm_version_regex = re.compile(r"^(.*?): (.*)")

        for line in tmp:
            match_tmp = kubeadm_version_regex.match(line)
            if match_tmp is None:
                continue
            if match_tmp[1] == "kubeadm":
                version = match_tmp[2]
                break

        if not version:
            ansithemeprint([ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(": Failed to get ", "default"),
                            ANSIThemeStr("kubeadm", "programname"),
                            ANSIThemeStr(" package version from control plane at "
                                         f"{control_plane_ip}; aborting.", "default")], stderr=True)
            sys.exit(errno.ENOENT)

        # First remove the distro revision
        major_minor_patchrev, _pkgrev = version.split("-")
        # Now split the version tuple
        version_major, version_minor, _rest = major_minor_patchrev.split(".")
    elif k8s_distro == "rke2":
        vlist = get_control_planes()
        first_control_plane = vlist[0][0]
        node_data = kh.get_ref_by_kind_name_namespace(("Node", ""), first_control_plane, "")
        kubelet_version = deep_get(node_data, DictPath("status#nodeInfo#kubeletVersion"), "")
        match_tmp = re.match(r"^(v\d+)\.(\d+).*", kubelet_version)
        if match_tmp is None:
            ansithemeprint([ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(": Failed to get kubelet version from control plane; "
                                         "aborting.", "default")], stderr=True)
            sys.exit(errno.EBADMSG)
        version = f"{match_tmp[1]}.{match_tmp[2]}"
        version_major = match_tmp[1][1:]
        version_minor = match_tmp[2]
    return version, version_major, version_minor
