# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of directory entries.
"""

from datetime import datetime, UTC
import os
from pathlib import Path
from typing import Any

from clustermanagementtoolkit.cmtlib import disksize_to_human

from clustermanagementtoolkit.cmtpaths import HOMEDIR

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-locals,too-many-branches
def listgetter_dir(**kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Get a list of directory entries. If prefixes and/or suffixes are set,
    any entries not matching the prefixes/suffixes will be skipped.

        Parameters:
            dirpath (str): The path to get the directory entries from
            kind (str): The kind to set for the imported entries
            prefixes ([str]): A list of accepted prefixes
            suffixes ([str]): A list of accepted suffixes
            rotation_separator (str): If set, log rotation is assumed;
                                      the filename is then either
                                      [prefix]file[suffix] or
                                      [prefix]file[suffix][rotation_separator][count]
            types ([str]): A list of entry types to include; if empty all types will
                           be included; currently supported filters are [file, dir]
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The directory entries
                (int): The status for the request
    """
    status: int = 200

    dirpath = deep_get(kwargs, DictPath("dirpath"), "")
    types = deep_get(kwargs, DictPath("types"), [])
    # Substitute {HOME} for {HOMEDIR}
    if dirpath.startswith("{HOME}"):
        dirpath = dirpath.replace("{HOME}", HOMEDIR, 1)
    prefixes: list[str] = deep_get(kwargs, DictPath("prefixes"), [])
    suffixes: list[str] = deep_get(kwargs, DictPath("suffixes"), [])
    rotation_separator: str = deep_get(kwargs, DictPath("rotation_separator"), "")
    kind = deep_get(kwargs, DictPath("kind"))

    vlist: list[dict[str, Any]] = []

    # pylint: disable-next=too-many-nested-blocks
    if os.path.isdir(dirpath):
        for filename in os.listdir(dirpath):
            if prefixes and not filename.startswith(tuple(prefixes)):
                continue
            if suffixes and not filename.endswith(tuple(suffixes)):
                if not rotation_separator:
                    continue
                rotationfile = False
                for suffix in suffixes:
                    tmpsplit = filename.rsplit(suffix, maxsplit=1)
                    if len(tmpsplit) == 2 and tmpsplit[1] and tmpsplit[1][0] == rotation_separator:
                        try:
                            rotationindex = tmpsplit[1][1:]
                            int(rotationindex)
                            rotationfile = True
                        except ValueError:
                            continue
                        break
                if not rotationfile:
                    continue
            if types:
                if os.path.isfile(filename):
                    if "file" not in types:
                        continue
                elif os.path.isdir(filename):
                    if "dir" not in types:
                        continue
                else:
                    # We don't support other types in the filter
                    continue

            filepath: FilePath = FilePath(dirpath).joinpath(filename)
            filepath_entry: Path = Path(filepath)
            fstat: os.stat_result = filepath_entry.stat()
            mtime: datetime = datetime.fromtimestamp(fstat.st_mtime, tz=UTC)
            ctime: datetime = datetime.fromtimestamp(fstat.st_ctime, tz=UTC)
            filesize: str = disksize_to_human(fstat.st_size)

            vlist.append({
                "name": filename,
                "mtime": mtime,
                "ctime": ctime,
                "filesize": filesize,
                "ref": {
                    "name": filename,
                    "filepath": FilePath(filepath),
                    "filesize": filesize,
                    "mtime": mtime,
                    "ctime": ctime,
                },
                "kind": kind,
                "metadata": {
                    "uid": filepath,
                },
            })

    return vlist, status

# Used by listpad
