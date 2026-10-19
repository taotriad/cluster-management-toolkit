# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper that clears the screen.
"""

import errno
import subprocess  # nosec

from clustermanagementtoolkit.cmtio import secure_which

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityPolicy


def clear_screen() -> int:
    """
    Clear the screen.

        Returns:
            retval (int): 0 on success, errno on failure
    """
    try:
        cpath = secure_which(FilePath("/usr/bin/clear"), fallback_allowlist=[],
                             security_policy=SecurityPolicy.ALLOWLIST_STRICT)
    except FileNotFoundError:
        return errno.ENOENT

    return subprocess.run([cpath], check=False).returncode
