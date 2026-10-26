# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Allowlist for helpers that fetch candidate versions for updates.
"""

from collections.abc import Callable

from clustermanagementtoolkit.networkio.get_github_version import get_github_version

candidate_version_function_allowlist: dict[str, Callable] = {
    "get_github_version": get_github_version,
}
