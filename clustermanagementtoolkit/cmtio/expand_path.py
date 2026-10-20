# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a path/filename/partial filename, expand it to its full path.
"""

import os
from pathlib import Path

from clustermanagementtoolkit.cmtpaths import HOMEDIR

from clustermanagementtoolkit.cmttypes import FilePath


# pylint: disable-next=too-many-branches
def expand_path(path: str, search_paths: list[str] | None = None,
                suffixes: list[str] | None = None,
                fallback: str = "") -> tuple[FilePath, bool]:
    """
    Given a path, filename or partial filename, expand it to its full path.

        Parameters:
            path (str): A path, filename, or partial filename
            search_paths (list(str)): The list of paths to attempt
                                      when a naked filename is passed
            suffixes (list(str)): If partial_path doesn't exist,
                                  attempt the same path with suffix appended
            fallback (str): The path to use if the provided path is empty or doesn't exist
        Returns:
            (FilePath, bool):
                (FilePath): The full path
                (bool): True if successful, False if fallback is returned
    """
    partial_paths = []
    full_path = None

    if path is None or not path:
        return FilePath(fallback), False

    if path.startswith("{HOME}/"):
        partial_paths.append(os.path.join(HOMEDIR, path[len("{HOME}/"):]))
    elif "/" in path:
        partial_paths.append(path)
    else:
        if search_paths is None:
            return FilePath(fallback), False
        for search_path in search_paths:
            if search_path.startswith("{HOME}/"):
                search_path = os.path.join(HOMEDIR, search_path[len("{HOME}/"):])
            partial_paths.append(os.path.join(search_path, path))

    for partial_path in partial_paths:
        path_entry = Path(partial_path)
        if path_entry.is_file():
            full_path = partial_path
            break
        if suffixes is not None:
            for suffix in suffixes:
                partial_path_suffixed = f"{partial_path}{suffix}"
                path_entry = Path(partial_path_suffixed)
                if path_entry.is_file():
                    full_path = partial_path_suffixed
                    break
    if full_path is None:
        return FilePath(fallback), False

    return FilePath(full_path), True
