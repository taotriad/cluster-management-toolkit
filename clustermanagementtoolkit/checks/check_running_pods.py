# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any, cast, TypedDict

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.checks.get_pod_set import get_pod_set

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


class PodListType(TypedDict, total=False):
    """
    A list of possible and/or required pods, optionally with a note
    that can be used to explain special cases, exceptions, etc.

        Parameters:
            any_of ([(str, str)]): At least one of these pods must exist
            all_of ([(str, str)]): All of these pods must exist
            skip [str]: Ignore this test on the following Kubernetes distros
            note ([ANSIThemeStr]): Additional notes
    """
    any_of: list[tuple[str, str]]
    all_of: list[tuple[str, str]]
    skip: list[str]
    note: list[ANSIThemeStr]


required_pods: dict[str, list[PodListType]] = {
    "api-server": [
        {
            "any_of": [("kube-system", "kube-apiserver"),
                       ("openshift-apiserver", "apiserver")],
        },
    ],
    "coredns": [
        {
            "any_of": [("kube-system", "coredns"), ("", "dns-default"),
                       # This could theoretically give false positives
                       # since rke2 also has a pod called rke2-coredns-rke2-coredns-autoscaler
                       ("kube-system", "rke2-coredns")],
        },
    ],
    "etcd": [
        {
            "any_of": [("kube-system", "etcd"),
                       ("openshift-etcd", "etcd")],
        },
    ],
    "kube-controller-manager": [
        {
            "any_of": [("kube-system", "kube-controller-manager"),
                       ("openshift-kube-controller-manager", "kube-controller-manager")],
        },
    ],
    # DaemonSet
    "kube-proxy": [
        {
            "any_of": [("kube-system", "kube-proxy")],
            "skip": ["crc", "openshift"],
        },
    ],
    "kube-scheduler": [
        {
            # FIXME
            "any_of": [("kube-system", "kube-scheduler"), ("", "openshift-kube-scheduler")],
        },
    ],
    "CNI": [
        {
            # antrea; DaemonSet
            # FIXME
            "any_of": [("kube-system", "antrea-agent")],
        },
        {
            # calico; Deployment
            "any_of": [("", "calico-kube-controllers")],
        },
        {
            # canal; DaemonSet
            # FIXME
            "any_of": [("", "canal")],
        },
        {
            # cilium; Deployment
            # FIXME
            "any_of": [("", "cilium-operator")],
        },
        {
            # flannel; DaemonSet
            # FIXME
            "any_of": [("", "kube-flannel-ds")],
        },
        {
            # kilo; DaemonSet
            # FIXME
            "any_of": [("", "kilo")],
        },
        {
            # kube-ovn; DaemonSet
            # FIXME
            "any_of": [("", "kube-ovn-cni")],
        },
        {
            # kube-router; DaemonSet
            # FIXME
            "any_of": [("", "kube-router")],
        },
        {
            # ovn-kubernetes; DaemonSet
            # FIXME
            "any_of": [("", "ovnkube")],
        },
        {
            # sdn; DaemonSet
            # FIXME
            "any_of": [("", "sdn")],
        },
        {
            # weave; DaemonSet
            # FIXME
            "any_of": [("", "weave-net")],
        },
    ],
}


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def check_running_pods(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks what pods are running and their status.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
        Returns:
            (bool, int, int, int, int):
                (bool): Is this error severe enough that we should abort immediately?
                    (int): The new count of critical severity security issues
                    (int): The new count of error severity security issues
                    (int): The new count of warning severity security issues
                    (int): The new count of note severity security issues
    """
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)

    abort: bool = False

    ansithemeprint([ANSIThemeStr("\n[Checking required pods]", "phase")])

    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")

    k8s_distro, _status = kh.identify_k8s_distro()

    pods, _status = kh.get_list_by_kind_namespace(("Pod", ""), "")
    all_ok = True

    for rp, rp_data in required_pods.items():
        ansithemeprint([ANSIThemeStr("•", "separator"),
                        ANSIThemeStr(f" {rp}", "programname")])

        matches = []

        for rp_match in rp_data:
            any_of = deep_get(cast(dict, rp_match), DictPath("any_of"), [])
            all_of = deep_get(cast(dict, rp_match), DictPath("all_of"), [])

            skip = deep_get(cast(dict, rp_match), DictPath("skip"), [])
            additional_info = deep_get(cast(dict, rp_match), DictPath("note"), [])

            if k8s_distro in skip:
                ansithemeprint([ANSIThemeStr("  ", "default"),
                                ANSIThemeStr("Note", "note"),
                                ANSIThemeStr(": check for ", "default"),
                                ANSIThemeStr(f"{rp}", "programname"),
                                ANSIThemeStr(" is skipped for Kubernetes distro ", "default"),
                                ANSIThemeStr(f"{k8s_distro}", "programname")])
                break

            any_of_matches, all_of_matches = get_pod_set(cast(list[dict], pods), any_of, all_of)

            if any_of_matches or all_of_matches:
                matches.append((any_of_matches, all_of_matches))

        if not matches and not skip:
            if any_of and not any_of_matches:
                ansithemeprint([ANSIThemeStr("  ", "default"),
                                ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(":", "default")], stderr=True)
                ansithemeprint([ANSIThemeStr("    At least one of the following pods is "
                                             "expected to be running:", "default")], stderr=True)
                for expected_namespace, expected_name in any_of:
                    if not expected_namespace:
                        expected_namespace = "<any>"
                    ansithemeprint([ANSIThemeStr(f"      {expected_namespace}", "namespace"),
                                    ANSIThemeStr("::", "separator"),
                                    ANSIThemeStr(f"{expected_name}", "default")], stderr=True)
                all_ok = False
                error += 1

            if all_of and not all_of_matches:
                ansithemeprint([ANSIThemeStr("  ", "default"),
                                ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(":", "default")], stderr=True)
                ansithemeprint([ANSIThemeStr("    All of the following pods are expected to "
                                             "be running:", "default")], stderr=True)
                for expected_namespace, expected_name in any_of:
                    if not expected_namespace:
                        expected_namespace = "<any>"
                    ansithemeprint([ANSIThemeStr(f"      {expected_namespace}", "namespace"),
                                    ANSIThemeStr("::", "separator"),
                                    ANSIThemeStr(f"{expected_name}", "default")], stderr=True)
                all_ok = False
                error += 1

        if len(matches) > 1:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Warning", "warning"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    Multiple possibly conflicting options were "
                                         "detected for ", "default"),
                            ANSIThemeStr(f"{rp}", "programname"),
                            ANSIThemeStr(".\n", "default")], stderr=True)
            warning += 1
            all_ok = False

        if matches:
            all_pods: list[dict] = []

            for any_of_matches, all_of_matches in matches:
                all_pods += any_of_matches
                for objs in all_of_matches.values():
                    all_pods += objs

            first = True

            for obj in all_pods:
                pod_name = deep_get(obj, DictPath("metadata#name"), "")
                pod_namespace = deep_get(obj, DictPath("metadata#namespace"), "")
                pod_node = deep_get(obj, DictPath("spec#nodeName"), "<unset>")
                conditions = deep_get(obj, DictPath("status#conditions"), [])
                phase = deep_get(obj, DictPath("status#phase"), "")

                ready = "NotReady"
                for condition in conditions:
                    if deep_get(condition, DictPath("type"), "") == "Ready" and \
                            deep_get(condition, DictPath("status"), "False") == "True":
                        ready = "Ready"
                if phase != "Running" or ready != "Ready":
                    if first:
                        ansithemeprint([ANSIThemeStr("  ", "default"),
                                        ANSIThemeStr("Error", "error"),
                                        ANSIThemeStr(":", "default")], stderr=True)
                        ansithemeprint([ANSIThemeStr("    The following pods should be in "
                                                     "phase Running, "
                                                     "condition Ready:", "default")])
                        first = False
                    ansithemeprint([ANSIThemeStr("        ", "default"),
                                    ANSIThemeStr(f"{pod_namespace}", "namespace"),
                                    ANSIThemeStr("::", "separator"),
                                    ANSIThemeStr(f"{pod_name}", "namespace"),
                                    ANSIThemeStr(" (", "default"),
                                    ANSIThemeStr(f"{phase}", "emphasis"),
                                    ANSIThemeStr("; ", "separator"),
                                    ANSIThemeStr(f"{ready}", "emphasis"),
                                    ANSIThemeStr(")", "default"),
                                    ANSIThemeStr(" on node ", "default"),
                                    ANSIThemeStr(f"{pod_node}", "hostname")], stderr=True)
                    error += 1
                    all_ok = False

        if all_ok:
            ansithemeprint([ANSIThemeStr("    OK\n", "success")])
        elif additional_info:
            ansithemeprint([ANSIThemeStr("    ", "default")] + additional_info)

    print()

    return abort, critical, error, warning, note
