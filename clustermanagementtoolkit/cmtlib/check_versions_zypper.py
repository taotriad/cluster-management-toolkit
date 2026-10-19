# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re

from clustermanagementtoolkit.cmtio import execute_command_with_response
from clustermanagementtoolkit.cmtio import secure_which

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityPolicy


# pylint: disable-next=too-many-locals
def check_versions_zypper(packages: list[str]) -> list[tuple[str, str, str, list[str]]]:
    """
    Given a list of packages, return installed, candidate, and all available versions.

        Parameters:
            packages ([str]): A list of packages to get versions for
        Returns:
            ([(str, str, str, [str])]): A list of package versions
    """
    versions = []
    versions_dict: dict[str, dict] = {}

    zypper_path = secure_which(FilePath("/usr/bin/zypper"),
                               fallback_allowlist=["/usr/bin"],
                               security_policy=SecurityPolicy.ALLOWLIST_RELAXED)
    args = [zypper_path, "search", "-s", "-x"] + packages
    response, _retval = execute_command_with_response(args)
    split_response = response.splitlines()

    # il | kubernetes1.28-kubeadm | package | 1.28.3-150400.5.1 | x86_64 | kubic
    # i | kubernetes1.28-kubeadm | package | 1.28.3-150400.5.1 | x86_64 | kubic
    package_version = re.compile(r"^(.).? \| (\S+) +\| package +\| (\S+) +\|.*")

    for line in split_response:
        if (tmp := package_version.match(line)):
            package = tmp[2]
            version = tmp[3]

            if package not in versions_dict:
                versions_dict[package] = {
                    "installed": "<none>",
                    "candidate": "<none>",
                    "available": [],
                }

            if tmp[1] == "i":
                versions_dict[package]["installed"] = version
            versions_dict[package]["available"].append(version)

    # Now summarise
    for package, data in versions_dict.items():
        installed = data["installed"]
        available = data["available"]
        if available:
            candidate = available[0]
        if candidate == installed:
            candidate = ""
        versions.append((package, data["installed"],
                         candidate, list(reversed(data["available"]))))

    return versions
