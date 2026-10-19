# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate that an argument is a boolean.
"""

from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtvalidators.set_programname import get_programname


def validator_bool(value: Any, error_on_failure: bool = True) -> tuple[bool, bool]:
    """
    Checks whether the value represents a bool.
    Note: this validator is not meant to validate all forms of truthiness; only user input.

        Parameters:
            value (any): The representation of value
            error_on_failure (bool): Print an error message on failure
        Returns:
            (bool, bool):
                (bool): True if the value can be represented as bool, False if not
                (bool): True if value is True, False if value is False
    """
    programname = get_programname()

    result = False
    retval = False

    match value:
        case False | 0 | "0" | "n" | "no" | "false":
            result = True
            retval = False
        case True | 1 | "1" | "y" | "yes" | "true":
            result = True
            retval = True
        case _:
            if error_on_failure:
                ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                                ANSIThemeStr(": “", "default"),
                                ANSIThemeStr(f"{value}", "option"),
                                ANSIThemeStr("“ is not a boolean.", "default")], stderr=True)

    return result, retval
