# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helpers used by various components of CMT that require imports that cannot
be satisfied before all components are installed.
"""

from clustermanagementtoolkit.cmtlib_ext.get_package_versions import get_package_versions

__all__ = [
    "get_package_versions",
]
