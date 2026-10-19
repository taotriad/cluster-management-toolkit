# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate that an argument is a CIDR.
"""

import sys
from typing import Any

try:
    import validators
    has_validators: bool = True  # pylint: disable=invalid-name
except ModuleNotFoundError:
    has_validators = False  # pylint: disable=invalid-name
    print("ModuleNotFoundError: Could not import validators; "
          "you may need to (re-)run `cmt-install.py` "
          "or `pip3 install validators`; disabling IP-address validation.\n", file=sys.stderr)

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cmtvalidators.set_programname import get_programname


def validator_cidr(value: str, **kwargs: Any) -> bool:
    """
    Validate a string to see if it's a valid CIDR.

        Parameters:
            value (str): The string to validate
            **kwargs (dict[str, Any]): Keyword arguments
                error_on_failure (bool): Show an error message on failure
        Returns:
            (bool): True if valid, False if invalid
    """
    error_on_failure: bool = deep_get(kwargs, DictPath("error_on_failure"), True)
    programname = get_programname()
    valid = False

    if "/" in value:
        ip, netmask = value.split("/")
        if has_validators:
            valid_ipv4_address = validators.ipv4(ip)
            valid_ipv6_address = validators.ipv6(ip)
        else:  # pragma: no cover
            valid_ipv4_address = True
            valid_ipv6_address = True
        try:
            if valid_ipv4_address and 0 < int(netmask) <= 32:
                valid = True
            if valid_ipv6_address and 0 < int(netmask) <= 128:
                valid = True
        except ValueError:
            pass

    if not valid and error_on_failure:
        ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                        ANSIThemeStr(": “", "default"),
                        ANSIThemeStr(f"{value}", "option"),
                        ANSIThemeStr("“ is not a valid POD Network CIDR.", "default")],
                       stderr=True)
    return valid
