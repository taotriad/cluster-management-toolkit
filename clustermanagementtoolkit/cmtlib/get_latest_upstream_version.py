# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Fetch the upstream version for an upstream component.
"""

from clustermanagementtoolkit import cmtpaths

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import SecurityChecks
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
    # This is to allow use of ansithemeprint from cmt-install.py.
    # pylint: disable-next=import-outside-toplevel
    from clustermanagementtoolkit import cmtio_yaml

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
            dict(cmtio_yaml.secure_read_yaml(cmtpaths.VERSION_CANDIDATES_FILE,
                                             checks=security_checks))
    except (FileNotFoundError, TypeError):
        candidate_versions = {}

    return deep_get(candidate_versions, DictPath(f"{component}#release"), "")
