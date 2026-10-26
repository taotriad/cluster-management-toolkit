# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Scan hosts for SSH-keys and add them to known_hosts.
"""

import errno
import os
from pathlib import Path
import re
import socket
import sys

import paramiko

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtpaths import SSH_DIR

from clustermanagementtoolkit.cmttypes import FilePath


def scan_and_add_ssh_keys(hosts: list[str]) -> None:
    """
    Scan hosts and add their public ssh keys to .ssh/known_hosts

        Parameters:
            hosts ([str]): A list of hostnames
    """
    known_hosts = FilePath(os.path.join(SSH_DIR, "known_hosts"))

    # Note: Paramiko seems to have issues if .ssh/known_hosts does not exist,
    # so "touch" the file just in case.
    old_umask = os.umask(0o077)
    Path(known_hosts).touch(mode=0o600, exist_ok=True)
    os.umask(old_umask)

    try:
        hostfile = paramiko.HostKeys(filename=known_hosts)
    except OSError:
        ansithemeprint([ANSIThemeStr("Critical", "critical"),
                        ANSIThemeStr(": Failed to open/read “", "default"),
                        ANSIThemeStr(known_hosts, "path"),
                        ANSIThemeStr("“; aborting.", "default")], stderr=True)
        sys.exit(errno.EIO)

    for host in hosts:
        try:
            with paramiko.Transport(host) as transport:
                transport.connect()
                key = transport.get_remote_server_key()
        except socket.gaierror as e:
            if str(e) in ("[Errno -2] Name or service not known",
                          "[Errno -3] Temporary failure in name resolution",
                          "[Errno -5] No address associated with hostname"):
                continue
            if (re_tmp := re.match(r"^\[Errno (-\d+)\] (.+)", str(e))) is not None:
                ansithemeprint([ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(": ", "default"),
                                ANSIThemeStr(f"{re_tmp[2]} (hostname: ", "default"),
                                ANSIThemeStr(f"{host}", "hostname"),
                                ANSIThemeStr("); aborting.", "default")],
                               stderr=True)
            else:
                ansithemeprint([ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(": Could not extract errno from ", "default"),
                                ANSIThemeStr(f"{e}; aborting.", "default")], stderr=True)
            sys.exit(errno.ENOENT)
        except paramiko.SSHException as e:
            ansithemeprint([ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(": Failed to get server key from remote host ",
                                         "default"),
                            ANSIThemeStr(host, "hostname"),
                            ANSIThemeStr(f": {e}; aborting.", "default")], stderr=True)
            sys.exit(errno.EIO)

        hostfile.add(hostname=host, key=key, keytype=key.get_name())

    try:
        hostfile.save(filename=known_hosts)
    except OSError:
        ansithemeprint([ANSIThemeStr("Critical", "critical"),
                        ANSIThemeStr(": Failed to save modifications to “", "default"),
                        ANSIThemeStr(known_hosts, "path"),
                        ANSIThemeStr("“; aborting.", "default")], stderr=True)
        sys.exit(errno.EIO)
