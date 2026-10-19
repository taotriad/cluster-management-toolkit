# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import errno
import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtio import secure_which

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityPolicy
from clustermanagementtoolkit.cmttypes import deep_get


def identify_distro(**kwargs: Any) -> str:
    """
    Identify what distro (Debian, Red Hat, SUSE, etc.) is in use.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            (str): The identified distro; empty if no distro could be identified
    """
    exit_on_failure = deep_get(kwargs, DictPath("exit_on_failure"), True)
    error_on_failure = deep_get(kwargs, DictPath("error_on_failure"), True)

    # Find out what distro this is run on
    try:
        distro_path = secure_which(FilePath("/etc/os-release"),
                                   fallback_allowlist=["/usr/lib", "/lib"],
                                   security_policy=SecurityPolicy.ALLOWLIST_STRICT,
                                   executable=False)
    except FileNotFoundError:  # pragma: no cover
        if error_on_failure:
            ansithemeprint([ANSIThemeStr("Error:", "error"),
                            ANSIThemeStr(" Cannot find an “", "default"),
                            ANSIThemeStr("os-release", "path"),
                            ANSIThemeStr("“ file to determine OS distribution; aborting.",
                                         "default")], stderr=True)
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.ENOENT)
        return ""

    distro = None

    distro_id_like = ""
    distro_id = ""

    with open(distro_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            key, value = line.split("=")
            value = value.strip("\"'")
            if key == "ID_LIKE":
                distro_id_like = value
                # If there's an ID_LIKE in the file we're done
                break
            if key == "ID":
                distro_id = value
                # But if we've only found an ID we cannot be sure
                # that there won't be an ID_LIKE later on

    if distro_id_like:
        distro = distro_id_like
    else:
        distro = distro_id

    if distro is None or not distro:
        if error_on_failure:
            ansithemeprint([ANSIThemeStr("Error:", "error"),
                            ANSIThemeStr(" Cannot read ID / ID_LIKE from “", "default"),
                            ANSIThemeStr("os-release", "path"),
                            ANSIThemeStr("“ file to determine OS distribution",
                                         "default")], stderr=True)
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.ENOENT)
        return ""

    if distro == "suse opensuse":
        distro = "suse"

    return distro
