# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Allowlist for release-note reformatters.
"""

from collections.abc import Callable

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.networkio.reformat_github_release_notes import reformat_github_release_notes  # noqa: E501

reformatter_allowlist: dict[str, Callable] = {
    "reformat_github_release_notes": reformat_github_release_notes,
}
