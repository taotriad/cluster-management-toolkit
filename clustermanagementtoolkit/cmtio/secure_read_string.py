# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import cast

from clustermanagementtoolkit.cmtio.secure_read import secure_read

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks


def secure_read_string(path: FilePath, checks: list[SecurityChecks] | None = None,
                       directory_is_symlink: bool = False, temporary: bool = False) -> str:
    """
    Read a string from a file in a safe manner.

        Parameters:
            path (FilePath): The path to read from
            checks ([SecurityChecks]): A list of checks that should be performed
            directory_is_symlink (bool): The directory that the path points to is a symlink
            temporary (bool): Is the file a tempfile?
                              If so we need to disable the check for parent permissions
        Returns:
            (str): The read string
        Raises:
            cmttypes.FilePathAuditError
    """
    return cast(str, secure_read(path, checks=checks,
                                 directory_is_symlink=directory_is_symlink,
                                 read_mode="r", temporary=temporary))
