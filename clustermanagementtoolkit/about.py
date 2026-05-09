#! /usr/bin/env python3
# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
This module holds version strings, copyright info, and license info
for Cluster Management Toolkit for Kubernetes
"""

import sys

COPYRIGHT: str = \
    "Copyright © 2019-2025 Intel Corporation\n" \
    "Copyright © 2025-2026 David Weinehall\n"

LICENSE: str = "This is free software; see the source for copying conditions.  There is NO\n" \
          "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."

PROGRAM_SUITE_NAME: str = "CMT"
PROGRAM_SUITE_FULL_NAME: str = "Cluster Management Toolkit for Kubernetes"
PROGRAM_SUITE_VERSION: str = "0.8.7"

UI_PROGRAM_NAME: str = "cmu"
UI_PROGRAM_VERSION: str = "0.5.5"

TOOL_PROGRAM_NAME: str = "cmt"
TOOL_PROGRAM_VERSION: str = "0.6.8"

INSTALL_PROGRAM_NAME: str = "cmt-install"
INSTALL_PROGRAM_VERSION: str = "0.13.9"

ADMIN_PROGRAM_NAME: str = "cmtadm"
ADMIN_PROGRAM_VERSION: str = "0.9.6"

INVENTORY_PROGRAM_NAME: str = "cmtinv"
INVENTORY_PROGRAM_VERSION: str = "0.4.9"

# We don't support Python-versions older than 3.11
version_info = sys.version_info
if version_info.major < 3 or version_info.minor < 11:  # pragma: no cover
    installed_version: str = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
    msg = "Critical: Minimum supported Python-version is 3.11.0.\n" \
          f"Installed version is {installed_version}" \
          "; aborting."
    sys.exit(msg)
