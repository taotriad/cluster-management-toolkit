# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit import about

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.kubernetes_helper import kubectl_get_version


# pylint: disable-next=too-many-statements,too-many-locals
def check_kubelet_and_kube_proxy_versions(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether the versions of kubelet and kube-proxy are acceptable.

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

    abort = False

    # Check kubelet version;
    # it can be up to two minor versions older than kube-apiserver,
    # but must not be newer

    mismatch = False

    _kubectl_major_version, _kubectl_minor_version, _kubectl_git_version, \
        server_major_version, server_minor_version, _server_git_version = kubectl_get_version()

    if server_major_version is None or server_minor_version is None:
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Critical", "error"),
                        ANSIThemeStr(":", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    Could not extract ", "default"),
                        ANSIThemeStr("kube-apiserver", "programname"),
                        ANSIThemeStr(" version (double-check that the server "
                                     "is running and that ", "default"),
                        ANSIThemeStr("https_proxy", "argument"),
                        ANSIThemeStr(" and  ", "default"),
                        ANSIThemeStr("no_proxy", "argument"),
                        ANSIThemeStr(" are correctly set); will abort.",
                                     "default")], stderr=True)
        abort = True
        critical += 1
        return abort, critical, error, warning, note

    # Kubernetes API based checks
    ansithemeprint([ANSIThemeStr("\n[Checking ", "phase"),
                    ANSIThemeStr("kubelet", "programname"),
                    ANSIThemeStr(" version]", "phase")])

    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError("check_kubelet_and_kube_proxy_versions() "
                               "called without kubernetes_helper")

    vlist, _status = kh.get_list_by_kind_namespace(("Node", ""), "")
    if vlist is None or _status != 200:
        vlist = []

    version_regex = re.compile(r"^v(\d+)\.(\d+)\..*")

    for node in vlist:
        node_name = deep_get(node, DictPath("metadata#name"))
        kubelet_version = deep_get(node, DictPath("status#nodeInfo#kubeletVersion"))
        tmp = version_regex.match(kubelet_version)

        kubelet_major_version = None
        kubelet_minor_version = None
        if tmp is not None:
            kubelet_major_version = int(tmp[1])
            kubelet_minor_version = int(tmp[2])
        else:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    Failed to extract ", "default"),
                            ANSIThemeStr("kubelet", "programname"),
                            ANSIThemeStr(" version on node ", "default"),
                            ANSIThemeStr(f"{node_name}", "hostname")], stderr=True)
            critical += 1
            mismatch = True

        if kubelet_major_version is not None and kubelet_major_version != 1:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Critical", "critical"),
                            ANSIThemeStr(": ", "default"),
                            ANSIThemeStr(about.PROGRAM_SUITE_NAME, "programname"),
                            ANSIThemeStr(" has not been tested for any other major version "
                                         "of Kubernetes than v1; node ", "default"),
                            ANSIThemeStr(f"{node_name}", "hostname"),
                            ANSIThemeStr(" runs ", "default"),
                            ANSIThemeStr("kubelet ", "programname"),
                            ANSIThemeStr("version ", "default"),
                            ANSIThemeStr(f"{kubelet_version}", "version")], stderr=True)
            critical += 1
            mismatch = True

        if kubelet_minor_version is not None and kubelet_minor_version > server_minor_version:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    The version of ", "default"),
                            ANSIThemeStr("kubelet", "programname"),
                            ANSIThemeStr(" (", "default"),
                            ANSIThemeStr(f"{kubelet_major_version}.{kubelet_minor_version}",
                                         "version"),
                            ANSIThemeStr(") on node ", "default"),
                            ANSIThemeStr(f"{node_name}", "hostname"),
                            ANSIThemeStr(" is newer than that of ", "default"),
                            ANSIThemeStr("kube-apiserver", "programname"),
                            ANSIThemeStr(" (", "default"),
                            ANSIThemeStr(f"{server_major_version}.{server_minor_version}",
                                         "version"),
                            ANSIThemeStr(");", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("       this is not supported.", "default")], stderr=True)
            error += 1
            mismatch = True
        elif kubelet_minor_version is not None and \
                server_minor_version - 2 <= kubelet_minor_version < server_minor_version:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Warning", "warning"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    The version of ", "default"),
                            ANSIThemeStr("kubelet", "programname"),
                            ANSIThemeStr(" (", "default"),
                            ANSIThemeStr(f"{kubelet_major_version}.{kubelet_minor_version}",
                                         "version"),
                            ANSIThemeStr(") on node ", "default"),
                            ANSIThemeStr(f"{node_name}", "hostname"),
                            ANSIThemeStr(" is a bit older than that of ", "default"),
                            ANSIThemeStr("kube-apiserver", "programname"),
                            ANSIThemeStr(" (", "default"),
                            ANSIThemeStr(f"{server_major_version}.{server_minor_version}",
                                         "version"),
                            ANSIThemeStr(");", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("         this is supported, but not recommended.",
                                         "default")], stderr=True)
            warning += 1
            mismatch = True
        elif kubelet_minor_version is not None and kubelet_minor_version < server_minor_version:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    The version of ", "default"),
                            ANSIThemeStr("kubelet", "programname"),
                            ANSIThemeStr(" (", "default"),
                            ANSIThemeStr(f"{kubelet_major_version}.{kubelet_minor_version}",
                                         "version"),
                            ANSIThemeStr(") on node ", "default"),
                            ANSIThemeStr(f"{node_name}", "hostname"),
                            ANSIThemeStr(" is much older than that of ", "default"),
                            ANSIThemeStr("kube-apiserver", "programname"),
                            ANSIThemeStr(" (", "default"),
                            ANSIThemeStr(f"{server_major_version}.{server_minor_version}",
                                         "version"),
                            ANSIThemeStr(");", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("       this is not supported.",
                                         "default")], stderr=True)
            error += 1
            mismatch = True

    if not mismatch:
        ansithemeprint([ANSIThemeStr("  OK", "ok")])

    return abort, critical, error, warning, note
