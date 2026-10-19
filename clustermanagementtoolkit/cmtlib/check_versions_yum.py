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
def check_versions_yum(packages: list[str]) -> list[tuple[str, str, str, list[str]]]:
    """
    Given a list of packages, return installed, candidate, and all available versions.

        Parameters:
            packages ([str]): A list of packages to get versions for
        Returns:
            ([(str, str, str, [str])]): A list of package versions
    """
    versions = []
    versions_dict: dict[str, dict] = {}

    yum_path = secure_which(FilePath("/usr/bin/yum"),
                            fallback_allowlist=["/usr/bin"],
                            security_policy=SecurityPolicy.ALLOWLIST_RELAXED)
    args = [yum_path, "-y", "-q", "list", "--showduplicates"] + packages
    response, _retval = execute_command_with_response(args)
    split_response = response.splitlines()

    package_version = re.compile(r"^([^.]+)[^\s]+[\s]+([^\s]+).*")

    section = ""

    for line in split_response:
        if line.lower() == "installed packages":
            section = "installed"
            continue
        if line.lower() == "available packages":
            section = "available"
            continue
        tmp = package_version.match(line)
        if tmp is not None:
            package = tmp[1]
            version = tmp[2]

            if package not in versions_dict:
                versions_dict[package] = {
                    "installed": "<none>",
                    "candidate": "<none>",
                    "available": [],
                }

            if section == "installed":
                versions_dict[package]["installed"] = version
            elif section == "available":
                versions_dict[package]["available"].append(version)

    # Now summarise
    for package, data in versions_dict.items():
        candidate = "<none>"
        if data["available"]:
            candidate = data["available"][-1]
            if data["installed"] == candidate:
                candidate = ""
        versions.append((package, data["installed"],
                         candidate, list(reversed(data["available"]))))

    return versions
