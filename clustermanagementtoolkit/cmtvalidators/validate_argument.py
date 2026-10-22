# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate command line arguments based on types.
"""

import errno
import os
from pathlib import Path
import re
import sys

try:
    import validators
    has_validators: bool = True  # pylint: disable=invalid-name
except ModuleNotFoundError:
    has_validators = False  # pylint: disable=invalid-name
    # There's not much point warning about missing validators;
    # either cmt is correctly installed (but validators isn't available),
    # or something would've failed earlier.

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemearray_to_str
from clustermanagementtoolkit.ansithemeprint import ansithemeprint
from clustermanagementtoolkit.ansithemeprint import ansithemestr_join_list

from clustermanagementtoolkit.cmtpaths import HOMEDIR

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.cmtvalidators.set_programname import get_programname
from clustermanagementtoolkit.cmtvalidators.validate_name import validate_name
from clustermanagementtoolkit.cmtvalidators.validator_bool import validator_bool
from clustermanagementtoolkit.cmtvalidators.validator_cidr import validator_cidr
from clustermanagementtoolkit.cmtvalidators.validator_int import validator_int
from clustermanagementtoolkit.cmtvalidators.validator_path import validator_path
from clustermanagementtoolkit.cmtvalidators.validator_taint import validator_taint


# pylint: disable-next=too-many-branches,too-many-statements,too-many-locals
def validate_argument(arg: str, arg_string: list[ANSIThemeStr], options: dict) -> bool:
    """
    Validate an argument or argument list.

        Parameters:
            arg (str): The argument to validate
            arg_string (ansithemearray): A ansithemearray with the formatted
                                         representation of the expected data format
            options (dict): Options to pass to the validators
        Returns:
            (bool): True on success, False on failure
    """
    result = True

    validator = deep_get(options, DictPath("validator"), "")
    list_separator = deep_get(options, DictPath("list_separator"))
    minval, maxval = deep_get(options, DictPath("valid_range"), (None, None))
    allowlist = deep_get(options, DictPath("allowlist"), [])
    validator_regex = deep_get(options, DictPath("regex"), r"")
    exit_on_failure = deep_get(options, DictPath("exit_on_failure"), True)
    error_on_failure = deep_get(options, DictPath("error_on_failure"), True)
    programname = get_programname()

    if list_separator is None:
        arglist = [arg]
    else:
        arglist = arg.split(list_separator)

    for subarg in arglist:
        if validator == "cidr":
            if not (result := validator_cidr(subarg, error_on_failure=error_on_failure)):
                break
        elif validator in ("path", "path_file"):
            if subarg.startswith(f"~{os.path.sep}"):
                subarg = f"{HOMEDIR}{os.path.sep}{subarg[2:]}"
            if not (result := validator_path(subarg, error_on_failure=error_on_failure,
                                             types=["file"])):
                break
        elif validator == "path_file_or_dir":
            if subarg.startswith(f"~{os.path.sep}"):
                subarg = f"{HOMEDIR}{os.path.sep}{subarg[2:]}"
            if not (result := validator_path(subarg, error_on_failure=error_on_failure,
                                             types=["file", "dir"])):
                break
        elif validator in ("hostname", "hostname_or_path",
                           "hostname_ip_or_ansible_group",
                           "hostname_or_ip", "ip"):
            valid_dns_label = validate_name("dns-subdomain", subarg)
            valid_ansible_group = validate_name("ansible-group", subarg)
            if has_validators:
                valid_ipv4_address = validators.ipv4(subarg)
                valid_ipv6_address = validators.ipv6(subarg)
            else:  # pragma: no cover
                valid_ipv4_address = True
                valid_ipv6_address = True
            # If the DNS-label is not an IP-address
            # it cannot end with a fully numerical dns-subdomain.
            if not (valid_ipv4_address or valid_ipv6_address) \
                    and "." in subarg and subarg.split(".")[-1:][0].isnumeric():
                valid_dns_label = False

            if validator in ("hostname", "hostname_or_path") and not valid_dns_label:
                # If validation failed as subdomain we check if it's a valid path;
                # this will need deeper checks in the main function.
                if validator == "hostname_or_path" and Path(subarg).is_file():
                    break
                if error_on_failure:
                    ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                                    ANSIThemeStr(": “", "default"),
                                    ANSIThemeStr(f"{subarg}", "option"),
                                    ANSIThemeStr("“ is not a valid hostname or path.",
                                                 "default")], stderr=True)
                result = False
                break
            if validator == "ip" and not any((valid_ipv4_address, valid_ipv6_address)):
                if error_on_failure:
                    ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                                    ANSIThemeStr(": “", "default"),
                                    ANSIThemeStr(f"{subarg}", "option"),
                                    ANSIThemeStr("“ is not a valid IP-address.",
                                                 "default")], stderr=True)
                result = False
                break
            if validator == "hostname_or_ip" \
                    and not any((valid_dns_label, valid_ipv4_address, valid_ipv6_address)):
                if error_on_failure:
                    ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                                    ANSIThemeStr(": “", "default"),
                                    ANSIThemeStr(f"{subarg}", "option"),
                                    ANSIThemeStr("“ is neither a valid hostname "
                                                 "nor a valid IP-address.",
                                                 "default")], stderr=True)
                result = False
                break
            if validator == "hostname_ip_or_ansible_group" \
                    and not any((valid_dns_label, valid_ipv4_address,
                                 valid_ipv6_address, valid_ansible_group)):
                if error_on_failure:
                    ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                                    ANSIThemeStr(": “", "default"),
                                    ANSIThemeStr(f"{subarg}", "option"),
                                    ANSIThemeStr("“ is neither a valid hostname, "
                                                 "IP-address, nor Ansible group.",
                                                 "default")], stderr=True)
                result = False
                break
        elif validator in ("dns-label", "dns-subdomain"):
            if not (result := validate_name(validator, subarg)):
                break
        elif validator in ("taint", "untaint"):
            if not (result := validator_taint(subarg, validator,
                                              error_on_failure=error_on_failure)):
                break
        elif validator == "bool":
            result, _value = validator_bool(subarg, error_on_failure=error_on_failure)
            if not result:
                break
        elif validator == "int":
            if not (result := validator_int(minval, maxval, subarg,
                                            error_on_failure=error_on_failure)):
                break
        elif validator == "allowlist":
            result = subarg in allowlist
            if result is False:
                if error_on_failure:
                    ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                                    ANSIThemeStr(": “", "default"),
                                    ANSIThemeStr(f"{subarg}", "argument"),
                                    ANSIThemeStr("“ is not a valid argument for ", "default")]
                                   + arg_string + [ANSIThemeStr(".", "default")],
                                   stderr=True)
                    ansithemeprint([ANSIThemeStr("Valid options are: ",
                                                 "description")], stderr=True)
                    ansithemeprint(ansithemestr_join_list(allowlist, formatting="argument"),
                                   stderr=True)
                break
        elif validator == "regex":
            if re.match(validator_regex, subarg) is None:
                if error_on_failure:
                    ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                                    ANSIThemeStr(": “", "default"),
                                    ANSIThemeStr(f"{subarg}", "argument"),
                                    ANSIThemeStr("“ is not a valid argument for ", "default")]
                                   + arg_string + [ANSIThemeStr(".", "default")], stderr=True)
                result = False
                break
        elif validator == "url":
            tmp_arg = subarg
            if not tmp_arg.startswith("http"):
                tmp_arg = f"https://{arg}"

            # Workaround; it seems validators.url accepts usernames that start with "-"
            if subarg.startswith("-") or has_validators and not validators.url(tmp_arg):
                if error_on_failure:
                    ansithemeprint([ANSIThemeStr(f"{programname}", "programname"),
                                    ANSIThemeStr(": “", "default"),
                                    ANSIThemeStr(f"{subarg}", "option"),
                                    ANSIThemeStr("“ is not a valid URL.", "default")],
                                   stderr=True)
                result = False
                break
        elif validator == "":
            # We cannot use format_error_msg() here since we'd lose the formatting for arg_string
            unformatted_msg = f"{programname}: no validator defined for argument " + \
                              ansithemearray_to_str(arg_string) + "."
            formatted_msg = [[ANSIThemeStr(f"{programname}", "emphasis"),
                              ANSIThemeStr(": no validator defined for argument ", "default")]
                             + arg_string + [ANSIThemeStr(".", "default")]]

            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   formatted_msg=formatted_msg)
        else:
            msg = [
                [("validate_argument()", "emphasis"),
                 (" called with invalid argument(s):", "error")],
                [("Unknown value for ", "default"),
                 ("validator = ", "default"),
                 (f"{validator}", "argument")],
            ]

            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(msg)

            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   formatted_msg=formatted_msg)

    if not result and exit_on_failure:  # pragma: no cover
        sys.exit(errno.EINVAL)

    return result
