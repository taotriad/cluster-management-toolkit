# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate that an argument is an integer.
"""

import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.cmtvalidators.set_programname import get_programname


def validator_int(minval: int, maxval: int, value: Any, **kwargs: Any) -> bool:
    """
    Checks whether value can be represented as an integer,
    and whether it's within the range [min, max].

        Parameters:
            min (int): The minimum value
            max (int): The maximum value
            value (any): The representation of value
            **kwargs (dict[str, Any]): Keyword arguments
                error_on_failure (bool): Show an error message on failure
                exit_on_failure (bool): exit on failure
        Returns:
            (bool): True if the value can be represented as int, False if not
    """
    error_on_failure: bool = deep_get(kwargs, DictPath("error_on_failure"), True)
    programname = get_programname()

    try:
        value = int(value)
    except ValueError:
        if error_on_failure:
            ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                            ANSIThemeStr(": “", "default"),
                            ANSIThemeStr(f"{value}", "option"),
                            ANSIThemeStr("“ is not an integer.", "default")], stderr=True)
        return False

    if minval is None:
        minval = -sys.maxsize
        minval_str = "<any>"
    else:
        minval_str = str(minval)

    if maxval is None:
        maxval = sys.maxsize
        maxval_str = "<any>"
    else:
        maxval_str = str(maxval)

    if minval > maxval:
        raise ProgrammingError(f"minval {minval} > maxval {maxval}")

    if not minval <= int(value) <= maxval:
        if error_on_failure:
            ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                            ANSIThemeStr(": “", "default"),
                            ANSIThemeStr(f"{value}", "option"),
                            ANSIThemeStr("“ is not in the range [", "default"),
                            ANSIThemeStr(minval_str, "emphasis"),
                            ANSIThemeStr(", ", "default"),
                            ANSIThemeStr(maxval_str, "emphasis"),
                            ANSIThemeStr("].", "default")], stderr=True)
        return False
    return True
