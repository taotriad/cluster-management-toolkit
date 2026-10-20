# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Fetch the upstream version for an upstream component.
"""

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmtpaths import VERSION_CANDIDATES_FILE

from clustermanagementtoolkit.cmttypes import DictPath, SecurityChecks
from clustermanagementtoolkit.cmttypes import deep_get


def get_latest_upstream_version(component: str) -> str:
    """
    Fetch the upstream version for an upstream component.

        Parameters:
            component (str): The component to return the latest version for
        Returns:
            (str): The latest upstream component version;
                   or an empty string if the version could not be determined
    """
    if not component:
        return ""

    # We are OK with the file not existing
    security_checks = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.IS_FILE,
    ]

    try:
        candidate_versions = \
            dict(secure_read_yaml(VERSION_CANDIDATES_FILE, checks=security_checks))
    except (FileNotFoundError, TypeError):
        candidate_versions = {}

    return deep_get(candidate_versions, DictPath(f"{component}#release"), "")
