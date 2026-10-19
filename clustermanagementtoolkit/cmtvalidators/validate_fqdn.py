# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Validate that an argument is a FQDN/hostname.
"""

import re

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import HostNameStatus
from clustermanagementtoolkit.cmttypes.exceptions import ArgumentValidationError


# pylint: disable-next=too-many-return-statements,too-many-branches,too-many-statements
def validate_fqdn(fqdn: str, message_on_error: bool = False) -> HostNameStatus:
    """
    Verifies that a FQDN / hostname is valid.

        Parameters:
            fqdn (str): The FQDN / hostname to validate
            message_on_error (bool): Should an error message be printed on error?
        Returns:
            (HostNameStatus): The result of the validation; HostNameStatus.OK on success
    """
    if fqdn is None or len(fqdn) == 0:
        if message_on_error:
            msg = [ANSIThemeStr("Error", "error"),
                   ANSIThemeStr(": A FQDN or hostname cannot be empty.", "default")]
            ansithemeprint(msg, stderr=True)
        return HostNameStatus.DNS_SUBDOMAIN_EMPTY
    if "\x00" in fqdn:
        stripped_fqdn = fqdn.replace("\x00", "<NUL>")
        if message_on_error:
            msg = [ANSIThemeStr("Critical", "critical"),
                   ANSIThemeStr(": the FQDN / hostname ", "default"),
                   ANSIThemeStr(stripped_fqdn, "hostname")]
            msg += [ANSIThemeStr(" contains NUL-bytes (replaced here).\n"
                                 "This is either a programming error, a system error, "
                                 "file or memory corruption, or a deliberate attempt "
                                 "to bypass security; aborting.", "default")]
            ansithemeprint(msg, stderr=True)
        emsg = [[("validate_fqdn()", "emphasis"),
                 (": The FQDN / hostname ", "default"),
                 (stripped_fqdn, "hostname"),
                 (" contains NUL-bytes (replaced here).", "default")],
                [("This is either a programming error, a system error, "
                  + "file or memory corruption, ", "default"),
                 ("or a deliberate attempt to bypass security; aborting.", "default")]]
        raise ArgumentValidationError(formatted_msg=emsg)
    if len(fqdn) > 253:
        if message_on_error:
            msg = [ANSIThemeStr("Critical", "critical"),
                   ANSIThemeStr(": the FQDN / hostname ", "default"),
                   ANSIThemeStr(fqdn, "hostname")]
            msg = [ANSIThemeStr(" is invalid; ", "default"),
                   ANSIThemeStr("a FQDN cannot be more than 253 characters long.", "default")]
            ansithemeprint(msg, stderr=True)
        return HostNameStatus.DNS_SUBDOMAIN_TOO_LONG
    if fqdn != fqdn.lower():
        if message_on_error:
            msg = [ANSIThemeStr("Error", "error"),
                   ANSIThemeStr(": The FQDN / hostname ", "default"),
                   ANSIThemeStr(fqdn, "hostname"),
                   ANSIThemeStr(" is invalid; ", "default"),
                   ANSIThemeStr("a FQDN / hostname must be lowercase.", "default")]
            ansithemeprint(msg, stderr=True)
        return HostNameStatus.DNS_SUBDOMAIN_WRONG_CASE
    if fqdn.startswith(".") or fqdn.endswith(".") or ".." in fqdn:
        if message_on_error:
            msg = [ANSIThemeStr("Error", "error"),
                   ANSIThemeStr(": The FQDN / hostname ", "default"),
                   ANSIThemeStr(fqdn, "hostname"),
                   ANSIThemeStr(" is invalid; ", "default"),
                   ANSIThemeStr("a FQDN / hostname cannot begin or end with “.“, "
                                "and must not have consecutive “.“.", "default")]
            ansithemeprint(msg, stderr=True)
        return HostNameStatus.DNS_SUBDOMAIN_INVALID_FORMAT

    dnslabels = fqdn.split(".")
    dnslabel_regex = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")

    for dnslabel in dnslabels:
        if dnslabel.startswith("xn--"):
            if message_on_error:
                msg = [ANSIThemeStr("Error", "error"),
                       ANSIThemeStr(": The DNS label ", "default"),
                       ANSIThemeStr(dnslabel, "hostname"),
                       ANSIThemeStr(" is invalid; ", "default"),
                       ANSIThemeStr("a DNS label cannot start "
                                    "with the ACE prefix “xn--“.", "default")]
                ansithemeprint(msg, stderr=True)
            return HostNameStatus.DNS_LABEL_STARTS_WITH_IDNA

        # This indirectly checks non-IDNA labels for max length too
        idna_dnslabel = dnslabel
        try:
            idna_dnslabel = dnslabel.encode("idna").decode("utf-8", errors="replace")
        except UnicodeError as e:
            if "label too long" in str(e):
                if message_on_error:
                    msg = [ANSIThemeStr("Error", "error"),
                           ANSIThemeStr(": the DNS label ", "default"),
                           ANSIThemeStr(dnslabel, "hostname"),
                           ANSIThemeStr(" is invalid; ", "default")]
                    msg += [ANSIThemeStr("a DNS label cannot "
                                         "be more than 63 characters long.", "default")]
                    ansithemeprint(msg, stderr=True)
                return HostNameStatus.DNS_LABEL_TOO_LONG
            if "label empty or too long" in str(e):
                if message_on_error:
                    msg = [ANSIThemeStr("Error", "error"),
                           ANSIThemeStr(": the DNS label ", "default"),
                           ANSIThemeStr(dnslabel, "hostname"),
                           ANSIThemeStr(" is invalid; ", "default")]
                    msg += [ANSIThemeStr("a decoded Punycode (IDNA) DNS label cannot "
                                         "be more than 63 characters long.", "default")]
                    ansithemeprint(msg, stderr=True)
                return HostNameStatus.DNS_LABEL_PUNYCODE_TOO_LONG
            raise

        if dnslabel_regex.match(idna_dnslabel) is None:
            if message_on_error:
                msg = [ANSIThemeStr("Error", "error"),
                       ANSIThemeStr(": the DNS label ", "default"),
                       ANSIThemeStr(dnslabel, "hostname")]
                if idna_dnslabel != dnslabel:
                    msg += [ANSIThemeStr(" (Punycode: ", "default"),
                            ANSIThemeStr(idna_dnslabel, "hostname"),
                            ANSIThemeStr(")", "default")]
                msg += [ANSIThemeStr(" is invalid; a DNS label must "
                                     "be in the format ", "default"),
                        ANSIThemeStr("[a-z0-9]([-a-z0-9]*[a-z0-9])?", "hostname"),
                        ANSIThemeStr(" after Punycode decoding.", "default")]
                ansithemeprint(msg, stderr=True)
            return HostNameStatus.DNS_LABEL_INVALID_CHARACTERS
    if len(dnslabels) == 1:
        return HostNameStatus.OK

    if not (dnslabels[-1:][0][0].isascii()
            and dnslabels[-1:][0][0].isalpha() and len(dnslabels[-1:][0]) > 1):
        # The dnslabel is OK if either of these apply:
        # * It only has one field (it doesn't have a tld)
        # * The first character in the TLD is [a-z] and the the TLD is longer than 1 character
        if message_on_error:
            msg = [ANSIThemeStr("Error", "error"),
                   ANSIThemeStr(": The DNS label ", "default"),
                   ANSIThemeStr(fqdn, "hostname"),
                   ANSIThemeStr(" is invalid; ", "default"),
                   ANSIThemeStr("the TLD must start with [a-z] and "
                                "be at least 2 characters long.", "default")]
            ansithemeprint(msg, stderr=True)
        return HostNameStatus.DNS_TLD_INVALID

    return HostNameStatus.OK
