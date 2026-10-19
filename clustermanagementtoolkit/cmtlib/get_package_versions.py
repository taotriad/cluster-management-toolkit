# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re

from clustermanagementtoolkit import ansible_helper

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def get_package_versions(hostname: str) -> list[tuple[str, str]]:
    """
    Returns a list of predefined packages for a host.

        Parameters:
            hostname (str): The host to get package versions for
        Returns:
            ([(str, str)]): The list of package versions
    """
    package_versions: list[tuple[str, str]] = []

    if not isinstance(hostname, str):
        raise TypeError(f"hostname {hostname} is type: {type(hostname)}, expected str")

    get_versions_path = ansible_helper.get_playbook_path(FilePath("get_versions.yaml"))
    retval, ansible_results = ansible_helper.ansible_run_playbook_on_selection(get_versions_path,
                                                                               selection=[hostname])

    # Failing to retrieve package versions shouldn't be treated as a critical error,
    # except when debugging.
    if not ansible_results:
        raise ValueError(f"Error: Failed to get package versions from {hostname} "
                         f"(retval: {retval}); aborting.")

    tmp = []

    for result in deep_get(ansible_results, DictPath(hostname), []):
        if deep_get(result, DictPath("task"), "") == "Package versions":
            tmp = deep_get(result, DictPath("msg_lines"), [])
            break

    # If we fail to get package versions (the systems might be virtual),
    # return an empty version list.
    if not tmp:
        raise ValueError(f"Error: Received empty version data from {hostname} "
                         f"(retval: {retval}); aborting.")

    package_version_regex = re.compile(r"^(.*?): (.*)")

    for line in tmp:
        tmp2 = package_version_regex.match(line)
        if tmp2 is None:
            continue
        package = tmp2[1]
        version = tmp2[2]
        package_versions.append((package, version))

    return package_versions
