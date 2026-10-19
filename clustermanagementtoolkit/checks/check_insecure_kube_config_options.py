# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtpaths import KUBE_CONFIG_FILE

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


def check_insecure_kube_config_options(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether .kube/config has insecure options.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                cluster_name (str): The name of the cluster
                kubeconfig (dict): The kubeconfig file
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
                verbose (bool): True for verbose output about actions
                quiet_on_ok (bool): Only output messages when issues are found?
        Returns:
            (bool, int, int, int, int):
                (bool): Is this error severe enough that we should abort immediately?
                (int): The new count of critical severity security issues
                (int): The new count of error severity security issues
                (int): The new count of warning severity security issues
                (int): The new count of note severity security issues
    """
    cluster_name: str = deep_get(kwargs, DictPath("cluster_name"), "")
    kubeconfig: dict = deep_get(kwargs, DictPath("kubeconfig"), {})
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)
    verbose = deep_get(kwargs, DictPath("verbose"), True)
    quiet_on_ok = deep_get(kwargs, DictPath("quiet_on_ok"), False)

    abort = False

    if not cluster_name:
        raise ProgrammingError(f"{__name__}() called without cluster_name")

    if verbose:
        ansithemeprint([ANSIThemeStr("[Checking for insecure ", "phase"),
                        ANSIThemeStr(f"{KUBE_CONFIG_FILE}", "path"),
                        ANSIThemeStr(" options]", "phase")])

    insecureskiptlsverify = False

    for cluster in deep_get(kubeconfig, DictPath("clusters"), []):
        if deep_get(cluster, DictPath("name"), "") == cluster_name:
            insecureskiptlsverify = deep_get(cluster, DictPath("insecure-skip-tls-verify"), False)
            break

    if not insecureskiptlsverify:
        if not quiet_on_ok:
            ansithemeprint([ANSIThemeStr("  OK\n", "emphasis")])
    else:
        # Use critical for highlighting warning here, since the warning is so important
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(":", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    TLS verification has been disabled in ", "emphasis"),
                        ANSIThemeStr(f"{KUBE_CONFIG_FILE}", "path"),
                        ANSIThemeStr(";", "emphasis")], stderr=True)
        ansithemeprint([ANSIThemeStr("    this is a security threat.", "emphasis")], stderr=True)
        ansithemeprint([ANSIThemeStr("    If TLS verification is disabled other systems "
                                     "can impersonate", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    the control plane and thus perform Man in the Middle "
                                     "(MITM) attacks.", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    It is advised that you remove the ", "default"),
                        ANSIThemeStr("insecure-skip-tls-verify", "argument")], stderr=True)
        ansithemeprint([ANSIThemeStr("    option from ", "default"),
                        ANSIThemeStr(f"{KUBE_CONFIG_FILE}", "path"),
                        ANSIThemeStr(", unless this is a development cluster",
                                     "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    and you are absolutely certain that your "
                                     "network environment is safe.\n", "default")], stderr=True)
        critical += 1

    return abort, critical, error, warning, note
