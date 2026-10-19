# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return data from files.
"""

from pathlib import Path
import re
from typing import Any

from clustermanagementtoolkit.cmtio import secure_read_string

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmtpaths import HOMEDIR

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError


def __recurse_data(path: dict, obj: Any) -> Any:
    datapath = deep_get(path, DictPath("path"), "")
    pathtype = deep_get(path, DictPath("pathtype"), "raw")
    nextpath = deep_get(path, DictPath("data"), {})

    if pathtype == "raw":
        return obj
    if pathtype == "list":
        if obj is None or len(obj) < datapath:
            return obj
        data = obj[datapath]
    else:
        data = deep_get(obj, datapath)

    if not nextpath:
        return data

    return __recurse_data(nextpath, data)


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def listgetter_files(**kwargs: Any) -> tuple[list[str | dict[str, Any]], int | str | None]:
    """
    Custom listgetter mainly for use with the version data checker.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            (([dict[str, Any]], int)):
                ([str|dict[str, Any]]): The list of Kubernetes objects
                (int): The status for the Kubernetes request
    """
    paths = \
        deep_get_with_fallback(kwargs,
                               [DictPath("paths"),
                                DictPath("extra_values#_extra_data#paths")], [],
                               fallback_on_empty=True)
    file_not_found_status = \
        deep_get_with_fallback(kwargs,
                               [DictPath("file_not_found_status"),
                                DictPath("extra_values#_extra_data#file_not_found_status")],
                               "File not found", fallback_on_empty=True)
    skip_empty_paths = deep_get(kwargs, DictPath("skip_empty_paths"), False)
    vlist: list[str | dict[str, Any]] = []
    status = None

    for path in paths:
        filepath = deep_get(path, DictPath("filepath"), "")
        if "_obj" in kwargs:
            for substkey, substpath in deep_get(path, DictPath("substitutions"), {}).items():
                substval = deep_get(kwargs, DictPath(f"_obj#{substpath}"), "")
                filepath = filepath.replace(f"<<<{substkey}>>>", substval)
        filetype = deep_get(path, DictPath("filetype"), "text")
        matchtype = deep_get(path, DictPath("data#matchtype"), "all")
        regex = deep_get(path, DictPath("data#regex"))
        key = deep_get(path, DictPath("data#key"))

        # Substitute {HOME}/ for {HOMEDIR}
        if filepath.startswith(("{HOME}/", "{HOME}\\")):
            filepath = HOMEDIR.joinpath(filepath[len('{HOME}/'):])

        d: Any = ""

        try:
            if filetype == "yaml":
                try:
                    d = dict(secure_read_yaml(filepath))
                except TypeError:
                    d = {}
            else:
                d = secure_read_string(filepath)
        except FilePathAuditError as e:
            if "SecurityStatus.PARENT_DOES_NOT_EXIST" in str(e) \
                    or "SecurityStatus.DOES_NOT_EXIST" in str(e):
                if status is None:
                    status = file_not_found_status
                continue
            raise

        if not d:
            continue

        # We've successfully read data at least once
        status = "OK"

        # Get the mtime of the file
        p = Path(FilePath(filepath))
        mtime = p.stat().st_mtime

        item: dict[str, Any] = {key: []}
        # pylint: disable-next=too-many-nested-blocks
        if filetype == "text":
            if regex:
                match = False
                for line in d.splitlines():
                    if (re_tmp := re.match(regex, line)):
                        for group in re_tmp.groups():
                            if group:
                                item[key].append(group)
                        match = True
                        if matchtype == "first":
                            if len(item[key]) == 1:
                                item[key] = item[key][0]
                            break
                if not match:
                    continue
            else:
                item = d
        else:
            item = __recurse_data(path, d)
        if (item is None or not item) and skip_empty_paths:
            continue
        extra_data = deep_get(path, DictPath("_extra_data"), {})
        extra_data["mtime"] = mtime

        if extra_data and isinstance(item, dict):
            item = {**item, "_extra_data": extra_data}

        vlist.append(item)

    return vlist, status
