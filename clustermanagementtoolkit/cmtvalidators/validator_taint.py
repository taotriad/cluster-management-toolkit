# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate that an argument is a Kubernetes taint.
"""

from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint
from clustermanagementtoolkit.ansithemeprint import ansithemestr_join_list

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cmtvalidators.set_programname import get_programname
from clustermanagementtoolkit.cmtvalidators.validate_name import validate_name


# pylint: disable-next=too-many-branches
def validator_taint(string: str, validator: str, **kwargs: Any) -> bool:
    """
    Validate a string to see if it's a valid taint.

        Parameters:
            string (str): The string to validate
            **kwargs (dict[str, Any]): Keyword arguments
                error_on_failure (bool): Show an error message on failure
        Returns:
            (bool): True if valid, False if invalid
    """
    error_on_failure = deep_get(kwargs, DictPath("error_on_failure"), True)
    programname = get_programname()
    valid = True

    # Format: dns-subdomain[:dns-label]={NoSchedule,PreferNoSchedule,NoExecute}
    if ":" in string:
        key_value, effect = string.split(":", maxsplit=1)
    else:
        key_value = string
        effect = ""

    if "=" in key_value:
        key, value = key_value.split("=", maxsplit=1)
    else:
        key = key_value
        value = ""

    valid_key = validate_name("dns-subdomain", key)
    if value:
        valid_value = validate_name("dns-label", value)
    else:
        valid_value = True

    valid_effects = ("NoSchedule", "PreferNoSchedule", "NoExecute")
    valid_effect = effect in valid_effects
    if not effect and validator == "untaint":
        valid_effect = True

    if not valid_key:
        if error_on_failure:
            ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                            ANSIThemeStr(": “", "default"),
                            ANSIThemeStr(f"{key}", "option"),
                            ANSIThemeStr("“ is not a valid taint-key.", "default")],
                           stderr=True)
        valid = False
    if not valid_value:
        if error_on_failure:
            ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                            ANSIThemeStr(": “", "default"),
                            ANSIThemeStr(f"{value}", "option"),
                            ANSIThemeStr("“ is not a valid taint-value.", "default")],
                           stderr=True)
        valid = False
    if not valid_effect:
        if error_on_failure:
            ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                            ANSIThemeStr(": “", "default"),
                            ANSIThemeStr(f"{effect}", "option"),
                            ANSIThemeStr("“ is not a valid taint-effect.", "default")],
                           stderr=True)
            ansithemeprint([ANSIThemeStr("Valid options are: ", "description")],
                           stderr=True)
            ansithemeprint(ansithemestr_join_list(valid_effects, formatting="argument"),
                           stderr=True)
        valid = False
    return valid
