# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate that an argument is a Kubernetes name.
"""

import os
import re

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-branches
def validate_name(rtype: str, name: str) -> bool:
    """
    Given a name validate whether it is valid for the given type.

        Parameters:
            rtype (str): The resource type; valid types are:
                         dns-label
                         dns-subdomain
                         path-segment
                         port-name
                         ansible-group
            name (str): The name to check for validity
        Returns:
            (bool): True if valid, False if invalid
    """
    invalid = False
    maxlen = -1

    if name is None:
        return False

    name_regex = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    portname_regex = re.compile(r"^([a-z0-9]+[a-z0-9-].*[a-z0-9]|[a-z0-9])$")
    ansible_group_regex = re.compile(r"^([a-zA-Z]+[a-zA-Z0-9_]*)$")

    if rtype in ("dns-subdomain", "dns-label"):
        if rtype == "dns-label":
            maxlen = 63
            if "." in name:
                invalid = True
        else:
            maxlen = 253

        # A dns-subdomain can be at most 253 characters long
        # and cannot start or end with "-"; it must be made up
        # of valid dns-labels; each of which are separated by "."
        # and have to meet the same standards as a dns-label
        labels = name.lower().split(".")

        for label in labels:
            if len(label) == 0 or len(label) > 63:
                invalid = True
                break

            if name_regex.match(label) is None:
                invalid = True
    elif rtype == "path-segment":
        if name in (".", "..") or "/" in name or "%" in name:
            invalid = True
        maxlen = os.pathconf("/", "PC_NAME_MAX")
    elif rtype == "port-name":
        # Any name containing adjacent "-" is invalid
        if "--" in name:
            invalid = True
        # As is any port-name that does not contain any character in [a-z]
        if portname_regex.match(name.lower()) is None:
            invalid = True
        # A portname can be at most 15 characters long
        # and cannot start or end with "-"
        if name_regex.match(name.lower()) is None:
            invalid = True
        maxlen = 15
    elif rtype == "ansible-group":
        if ansible_group_regex.match(name) is None:
            invalid = True
    else:
        msg = [
            [("validate_name()", "emphasis"),
             (" called with invalid argument(s):", "error")],
            [("Unknown value for ", "default"),
             ("rtype = ", "default"),
             (f"{rtype}", "argument")],
        ]

        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(msg)

        raise ProgrammingError(unformatted_msg,
                               severity=LogLevel.ERR,
                               formatted_msg=formatted_msg)

    return not invalid and len(name) <= maxlen
