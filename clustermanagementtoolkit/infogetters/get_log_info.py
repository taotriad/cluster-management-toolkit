# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from datetime import datetime, UTC
import os
from typing import Any, cast

from clustermanagementtoolkit.ansible_helper import ansible_get_logs

from clustermanagementtoolkit.cmtio import execute_command_with_response
from clustermanagementtoolkit.cmtio import secure_which

from clustermanagementtoolkit.cmtio_yaml import json_loads

from clustermanagementtoolkit.cmtpaths import BINDIR

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityPolicy
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=unused-argument,too-many-locals
def get_log_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for logs.

        Parameters:
            **kwargs (dict): Additional parameters
        Returns:
            ([dict]): A list with info
    """
    info: list[dict] = []

    # Fetch kubelet log, if available (for now only useful if run on the control plane)
    sudo_path: FilePath = secure_which(FilePath("sudo"),
                                       fallback_allowlist=["/bin", "/usr/bin"],
                                       security_policy=SecurityPolicy.ALLOWLIST_STRICT)
    journalctl_path: FilePath = secure_which(FilePath(os.path.join(BINDIR, "journalctl")),
                                             fallback_allowlist=["/bin", "/usr/bin"],
                                             security_policy=SecurityPolicy.ALLOWLIST_STRICT)
    # Pass -n to sudo to ensure that it doesn't try to authenticate interactively;
    # let it fail instead if it cannot sudo non-interactively.
    args: list[str] = [sudo_path, "-n", journalctl_path, "--no-pager", "-o", "json"]

    logs: list[tuple[str, str, list[str], str]] = [
        ("Latest boot, last 1h", "[dmesg]",
         ["-k", "-b", "--lines", "10000"], "glog"),
        ("Latest 1000 lines", "[kubelet]",
         ["--lines", "1000", "-u", "kubelet"], "glog"),
        ("Latest 1000 lines", "[rke2-server]",
         ["--lines", "1000", "-u", "rke2-server"], "key_value"),
        ("Latest 1000 lines", "[containerd]",
         ["--lines", "1000", "-u", "containerd"], "key_value"),
        ("Latest 1000 lines", "[cri-o]",
         ["--lines", "1000", "-u", "crio"], "key_value"),
    ]

    try:
        for name, action, log, parser in logs:
            response, retval = execute_command_with_response(args + log)
            if not response or retval:
                continue

            # The first entry in the obj list holds metadata;
            # the rest of the entries are strings
            split_response: list[Any] = [{
                # "parser": str
                # "name": str
                # "host": str
                # "created_at": datetime
                "parser": parser,
            }]
            split_response += response.splitlines()
            latestentry: str = cast(str, split_response[1])

            d = json_loads(latestentry)

            split_response[0]["name"] = deep_get(d, DictPath("SYSLOG_IDENTIFIER"), "<unknown>")
            hostname = deep_get(d, DictPath("_HOSTNAME"), "<unknown>")
            split_response[0]["host"] = hostname
            created_at = \
                datetime.fromtimestamp(int(deep_get(d, DictPath("__REALTIME_TIMESTAMP"))) / 1000000,
                                       tz=UTC)
            split_response[0]["created_at"] = created_at

            info.append({
                "name": f"<dynamic> {hostname}: {name}",
                "ref": {
                    "ref": split_response,
                    "kind": "__JournalctlLogView",
                },
                "action": action,
                "message": deep_get(d, DictPath("MESSAGE"), ""),
                "created_at": created_at,
                "log_type": "journalctl",
            })
    except FileNotFoundError:
        pass

    # Get the list of available Ansible logs
    ansible_logs = ansible_get_logs()

    # TODO(Here we might possibly want to insert other logs?)

    for name, action, ref, created_at in ansible_logs:
        log_type = "Ansible Play"
        info.append({
            "name": name,
            "ref": {
                "ref": ref,
                "kind": "__AnsibleLog",
            },
            "action": action,
            "created_at": created_at,
            "log_type": log_type,
            "__uid": name,
        })
    return info
