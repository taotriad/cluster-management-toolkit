# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Check whether the versions of the various Kubernetes components are within
acceptable range.
"""

import errno
import os
import sys
from typing import Any, cast

from clustermanagementtoolkit import about

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.kubernetes_helper import kubectl_get_version


# pylint: disable-next=too-many-statements,too-many-locals
def check_client_server_version_match(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether the versions of the various Kubernetes match properly.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
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
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)
    verbose: bool = deep_get(kwargs, DictPath("verbose"), True)
    quiet_on_ok: bool = deep_get(kwargs, DictPath("quiet_on_ok"), False)

    mismatch: bool = False
    abort: bool = False

    # Is the version of kubectl within one version of the cluster version?
    if verbose:
        ansithemeprint([ANSIThemeStr("[Checking client/server version match]", "phase")])

    _kubectl_major_version, kubectl_minor_version, kubectl_git_version, \
        server_major_version, server_minor_version, server_git_version = kubectl_get_version()

    if kubectl_git_version == "<unavailable>" or kubectl_minor_version is None:
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Critical", "critical"),
                        ANSIThemeStr(": Could not extract ", "default"),
                        ANSIThemeStr("kubectl", "programname"),
                        ANSIThemeStr(" version; will abort.\n", "default")], stderr=True)
        abort = True
        critical += 1
    elif verbose:
        ansithemeprint([ANSIThemeStr("         kubectl ", "programname"),
                        ANSIThemeStr("version: ", "default"),
                        ANSIThemeStr(f"{kubectl_git_version}", "version")])
    if server_git_version == "<unavailable>" \
            or server_major_version is None or server_minor_version is None:
        print()
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Critical", "critical"),
                        ANSIThemeStr(":", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    Could not extract ", "default"),
                        ANSIThemeStr("kube-apiserver", "programname"),
                        ANSIThemeStr(" version (double-check that the server is",
                                     "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    running and that ", "default"),
                        ANSIThemeStr("https_proxy", "argument"),
                        ANSIThemeStr(" and ", "default"),
                        ANSIThemeStr("no_proxy", "argument"),
                        ANSIThemeStr(" are correctly set); will abort.\n",
                                     "default")], stderr=True)
        https_proxy_env = os.getenv("https_proxy")
        no_proxy_env = os.getenv("no_proxy")
        ansithemeprint([ANSIThemeStr("      https_proxy", "argument"),
                        ANSIThemeStr(" (env): ", "default"),
                        ANSIThemeStr(f"{https_proxy_env}", "uri")], stderr=True)
        ansithemeprint([ANSIThemeStr("      no_proxy", "argument"),
                        ANSIThemeStr(" (env): ", "default"),
                        ANSIThemeStr(f"{no_proxy_env}\n", "uri")], stderr=True)
        abort = True
        critical += 1
    elif verbose:
        ansithemeprint([ANSIThemeStr("  kube-apiserver ", "programname"),
                        ANSIThemeStr("version: ", "default"),
                        ANSIThemeStr(f"{server_git_version}", "version")])
        print()

    if abort:
        return abort, critical, error, warning, note

    kubectl_minor_version = cast(int, kubectl_minor_version)
    server_major_version = cast(int, server_major_version)
    server_minor_version = cast(int, server_minor_version)

    if server_major_version != 1:
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Critical", "critical"),
                        ANSIThemeStr(": ", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr(f"    {about.PROGRAM_SUITE_NAME}", "programname"),
                        ANSIThemeStr(" has not been tested for any other major version of "
                                     "Kubernetes ", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    than ", "default"),
                        ANSIThemeStr("v1", "version"),
                        ANSIThemeStr("; aborting.", "default")], stderr=True)
        sys.exit(errno.ENOTSUP)

    if kubectl_minor_version > server_minor_version and \
            kubectl_minor_version == server_minor_version + 1:
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Note", "note"),
                        ANSIThemeStr(":", "default")])
        ansithemeprint([ANSIThemeStr("    The ", "default"),
                        ANSIThemeStr("kubectl", "programname"),
                        ANSIThemeStr(" version is one minor version newer than that of ",
                                     "default"),
                        ANSIThemeStr("kube-apiserver", "programname"),
                        ANSIThemeStr(";", "default")])
        ansithemeprint([ANSIThemeStr("    this is a supported configuration, "
                                     "but it is generally recommended to keep", "default")])
        ansithemeprint([ANSIThemeStr("    the versions in sync.\n", "default")])
        note += 1
        mismatch = True
    elif kubectl_minor_version > server_minor_version:
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(":", "default")])
        ansithemeprint([ANSIThemeStr("    The ", "default"),
                        ANSIThemeStr("kubectl", "programname"),
                        ANSIThemeStr(" version is more than one minor version newer than",
                                     "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    that of ", "default"),
                        ANSIThemeStr("kube-apiserver", "programname"),
                        ANSIThemeStr("; this might work, but it is generally recommended",
                                     "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    to keep the versions in sync.\n",
                                     "default")], stderr=True)
        warning += 1
        mismatch = True
    elif kubectl_minor_version < server_minor_version and \
            kubectl_minor_version + 1 == server_minor_version:
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(":", "default")])
        ansithemeprint([ANSIThemeStr("    The ", "default"),
                        ANSIThemeStr("kubectl", "programname"),
                        ANSIThemeStr(" version is one minor version older "
                                     "than that of ", "default"),
                        ANSIThemeStr("kube-apiserver", "programname"),
                        ANSIThemeStr(";", "default")])
        ansithemeprint([ANSIThemeStr("    this is a supported configuration, "
                                     "but it is generally recommended to keep", "default")])
        ansithemeprint([ANSIThemeStr("    the versions in sync.\n", "default")], stderr=True)
        warning += 1
        mismatch = True
    elif kubectl_minor_version < server_minor_version:
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Error", "error"),
                        ANSIThemeStr(":", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    The ", "default"),
                        ANSIThemeStr("kubectl", "programname"),
                        ANSIThemeStr(" version is much older than that of ", "default"),
                        ANSIThemeStr("kube-apiserver", "programname"),
                        ANSIThemeStr(";", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    this is ", "default"),
                        ANSIThemeStr("NOT", "emphasis"),
                        ANSIThemeStr(" supported and is likely to "
                                     "cause issues.\n", "default")], stderr=True)
        error += 1
        mismatch = True

    if not mismatch and not quiet_on_ok:
        ansithemeprint([ANSIThemeStr("  OK\n", "ok")])

    return abort, critical, error, warning, note
