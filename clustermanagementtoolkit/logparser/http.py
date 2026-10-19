# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
import sys
from typing import Any

try:
    import validators
    has_validators: bool = True  # pylint: disable=invalid-name
except ModuleNotFoundError:
    has_validators = False  # pylint: disable=invalid-name
    print("ModuleNotFoundError: Could not import validators; "
          "you may need to (re-)run `cmt-install.py` or `pip3 install validators`; "
          "disabling IP-address validation.\n", file=sys.stderr)

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators import format_address

from clustermanagementtoolkit.logparser.month_to_numerical import month_to_numerical


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def http(message: str, **kwargs: Any) -> tuple[str, LogLevel, list[ThemeRef | ThemeStr]]:
    """
    Format various http log style messages.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
                options (dict): Additional, rule specific, options
        Returns:
            (ThemeArray, LogLevel, str):
                (ThemeArray): The formatted string
                (LogLevel): The new loglevel
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    options: dict = deep_get(kwargs, DictPath("options"), {})

    reformat_timestamps = deep_get(options, DictPath("timestamp#reformat"), False)

    ipaddress = ""

    # If the message starts with a timestamp without a leading IP-address, skip this.
    if not message.startswith("["):  # noqa: SIM102
        # First try to check if it's an IP-address.
        # pylint: disable-next=line-too-long
        if (re_tmp := re.match(r"^([a-f0-9:][a-f0-9:.]+[a-f0-9])( - - .*)", message)) is not None:  # noqa: SIM102,E501
            # Just pass-through if validators isn't installed;
            # this might lead to false positives, but it's better than not working at all.
            if not has_validators or validators.ipv4(re_tmp[1]) or validators.ipv6(re_tmp[1]):
                ipaddress = re_tmp[1]
                message = re_tmp[2]

    # Short format
    if ipaddress:
        re_tmp = re.match(r"( - - )"                  # separator1
                          r"(\[)"                     # separator2
                          r"(\d\d)"                   # day
                          r"/"
                          r"([A-Z][a-z][a-z])"        # _month
                          r"/"
                          r"(\d{4})"                  # year
                          r" "
                          r"(\d\d:\d\d:\d\d)"         # hms
                          r"(\])"                     # separator3
                          r"(\s\")"                   # separator4
                          r"([A-Z]*?\s)"              # verb
                          r"(\S*?)"                   # address3
                          r"(\s\S*?)"                 # protocol
                          r"(\"\s)"                   # separator5
                          r"(\d+?)"                   # statuscode
                          r"(\s+[\d-]+?$)", message)  # separator6

        if re_tmp is not None:
            address1 = ipaddress
            fmt_address1 = format_address(ipaddress, selected=False)
            separator1 = re_tmp[1]
            separator2 = re_tmp[2]
            day = re_tmp[3]
            _month = re_tmp[4]
            month = month_to_numerical(_month)
            year = re_tmp[5]
            hms = re_tmp[6]
            if reformat_timestamps:
                ts = f"{year}-{month}-{day} {hms}"
            else:
                ts = f"{day}/{_month}/{year}:{hms}"
            separator3 = re_tmp[7]
            separator4 = re_tmp[8]
            verb = re_tmp[9]
            address3 = re_tmp[10]
            protocol = re_tmp[11]
            separator5 = re_tmp[12]
            statuscode = re_tmp[13]
            _statuscode = int(statuscode)
            if 100 <= _statuscode < 300:
                severity = LogLevel.NOTICE
            elif 300 <= _statuscode < 400:
                severity = LogLevel.WARNING
            else:
                severity = LogLevel.ERR
            separator6 = re_tmp[14]
            new_message: list[ThemeRef | ThemeStr] = fmt_address1 + [
                ThemeStr(separator1, ThemeAttr("logview", "severity_info")),
                ThemeStr(f"{separator2}{ts}{separator3}", ThemeAttr("logview", "timestamp")),
                ThemeStr(separator4, ThemeAttr("logview", "severity_info")),
                ThemeStr(verb, ThemeAttr("logview", "protocol")),
                ThemeStr(address3, ThemeAttr("logview", "uri")),
                ThemeStr(protocol, ThemeAttr("logview", "protocol")),
                ThemeStr(separator5, ThemeAttr("logview", "severity_info")),
                ThemeStr(statuscode,
                         ThemeAttr("logview", f"severity_{loglevel_to_name(severity).lower()}")),
                ThemeStr(separator6, ThemeAttr("logview", "severity_info")),
            ]

            return facility, severity, new_message

    if ipaddress:
        re_tmp = re.match(r"( - - )"
                          r"(\[)"
                          r"(\d\d)"
                          r"/"
                          r"([A-Z][a-z][a-z])"
                          r"/"
                          r"(\d{4})"
                          r":"
                          r"(\d\d:\d\d:\d\d)"
                          r"(\s\+\d{4}|\s-\d{4})"
                          r"(\])"
                          r"(\s\")"
                          r"([A-Z]*?\s)"
                          r"(\S*?)"
                          r"(\s\S*?)"
                          r"(\"\s)"
                          r"(\d+?)"
                          r"(\s+\d+?\s\")"
                          r"([^\"]*)"
                          r"(\")"
                          r"(\s|$)"
                          r"(\"|.*$)"
                          r"([^\"]*|$)"
                          r"(\"|$)"
                          r"(\s.*$|$)", message)

        if re_tmp is not None:
            address1 = ipaddress
            fmt_address1 = format_address(ipaddress, selected=False)
            separator1 = re_tmp[1]
            separator2 = re_tmp[2]
            day = re_tmp[3]
            _month = re_tmp[4]
            month = month_to_numerical(_month)
            year = re_tmp[5]
            hms = re_tmp[6]
            tz = re_tmp[7]
            if reformat_timestamps:
                ts = f"{year}-{month}-{day} {hms}{tz}"
            else:
                ts = f"{day}/{_month}/{year}:{hms}{tz}"
            separator3 = re_tmp[8]
            separator4 = re_tmp[9]
            verb = re_tmp[10]
            address3 = re_tmp[11]
            protocol = re_tmp[12]
            separator5 = re_tmp[13]
            statuscode = re_tmp[14]
            _statuscode = int(statuscode)
            if 100 <= _statuscode < 300:
                severity = LogLevel.NOTICE
            elif 300 <= _statuscode < 400:
                severity = LogLevel.WARNING
            else:
                severity = LogLevel.ERR
            separator6 = re_tmp[15]
            address4 = re_tmp[16]
            separator7 = re_tmp[17] + re_tmp[18] + re_tmp[19]
            address5 = re_tmp[20]
            separator8 = re_tmp[21]
            remainder = re_tmp[22]

            severity_name = f"severity_{loglevel_to_name(severity).lower()}"
            new_message = fmt_address1 + [
                ThemeStr(separator1, ThemeAttr("logview", "severity_info")),
                ThemeStr(f"{separator2}{ts}{separator3}", ThemeAttr("logview", "timestamp")),
                ThemeStr(separator4, ThemeAttr("logview", "severity_info")),
                ThemeStr(verb, ThemeAttr("logview", "protocol")),
                ThemeStr(address3, ThemeAttr("logview", "uri")),
                ThemeStr(protocol, ThemeAttr("logview", "protocol")),
                ThemeStr(separator5, ThemeAttr("logview", "severity_info")),
                ThemeStr(statuscode, ThemeAttr("logview", severity_name)),
                ThemeStr(separator6, ThemeAttr("logview", "severity_info")),
                ThemeStr(address4, ThemeAttr("logview", "uri")),
                ThemeStr(separator7, ThemeAttr("logview", "severity_info")),
            ]
            if address5 is not None:
                new_message.append(ThemeStr(address5, ThemeAttr("logview", "uri")))
                new_message.append(ThemeStr(separator8, ThemeAttr("logview", "severity_info")))
            if remainder is not None:
                new_message.append(ThemeStr(remainder, ThemeAttr("types", "generic")))

            return facility, severity, new_message

    # Alternate formats
    re_tmp = re.match(r"^\|\s+"
                      r"(\d{3})"         # statuscode
                      r"\s+\|\s+"
                      r"([0-9.]+)"       # duration
                      r"([^ ]*)"         # unit
                      r"\s+\|\s+"
                      r"([^:^\s]*)"      # hostname
                      r":(\d+?)"         # port
                      r"\s+\|\s+"
                      r"([A-Z]+)"        # verb
                      r"\s+"
                      r"(.*)", message)  # url

    if re_tmp is not None:
        statuscode = re_tmp[1]
        _statuscode = int(statuscode)
        if 100 <= _statuscode < 300:
            severity = LogLevel.NOTICE
        elif 300 <= _statuscode < 400:
            severity = LogLevel.WARNING
        else:
            severity = LogLevel.ERR
        duration = re_tmp[2]
        unit = re_tmp[3]
        hostname = re_tmp[4]
        port = re_tmp[5]
        verb = re_tmp[6]
        url = re_tmp[7]
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        new_message = [
            ThemeStr("| ", ThemeAttr("logview", "severity_info")),
            ThemeStr(statuscode, ThemeAttr("logview", severity_name)),
            ThemeStr(" | ", ThemeAttr("logview", "severity_info")),
            ThemeStr(duration, ThemeAttr("logview", "severity_info")),
            ThemeStr(unit, ThemeAttr("types", "unit")),
            ThemeStr(" | ", ThemeAttr("logview", "severity_info"))]
        new_message += format_address(hostname, selected=False) + [
            ThemeRef("separators", "port"),
            ThemeStr(port, ThemeAttr("types", "port")),
            ThemeStr(" | ", ThemeAttr("logview", "severity_info")),
            ThemeStr(verb, ThemeAttr("logview", "protocol")),
            ThemeStr(" ", ThemeAttr("logview", "severity_info")),
            ThemeStr(url, ThemeAttr("logview", "uri")),
        ]
        return facility, severity, new_message

    re_tmp = re.match(r"^\["
                      r"(\d{4}-\d\d-\d\d)"
                      r"T"
                      r"(\d\d:\d\d:\d\d\.\d\d\d)Z"
                      r"\] \""
                      r"([A-Z]+)"
                      r"\s"
                      r"([^\s]+)"
                      r"\s"
                      r"([^\"]+)"
                      r"\" "
                      r"([\d]+)"
                      r" ([^\s]+)"
                      r" ([^\s]+)"
                      r" ([^\s]+)"
                      r" ([^\s]+)"
                      r" ([^\s]+) "
                      r"\"([^\"]+)\" "
                      r"\"([^\"]+)\" "
                      r"\"([^\"]+)\" "
                      r"\"([^\"]+)\" "
                      r"\"([^\"]+)\"", message)

    if re_tmp is not None:
        date = re_tmp[1]
        hmsms = re_tmp[2]

        if reformat_timestamps:
            ts = f"{date} {hmsms} +0000"
        else:
            ts = f"{date}T{hmsms}Z"

        verb = re_tmp[3]
        address1 = re_tmp[4]
        protocol = re_tmp[5]
        statuscode = re_tmp[6]
        _statuscode = int(statuscode)
        if 100 <= _statuscode < 300:
            severity = LogLevel.NOTICE
        elif 300 <= _statuscode < 400:
            severity = LogLevel.WARNING
        else:
            severity = LogLevel.ERR
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"

        number0 = re_tmp[7]
        number1 = re_tmp[8]
        number2 = re_tmp[9]
        number3 = re_tmp[10]
        number4 = re_tmp[11]
        client = re_tmp[12]
        str0 = re_tmp[13]
        str1 = re_tmp[14]
        str2 = re_tmp[15]
        str3 = re_tmp[16]

        new_message = [
            ThemeStr(f"[{ts}] ", ThemeAttr("logview", "timestamp")),
            ThemeStr("\"", ThemeAttr("logview", "severity_info")),
            ThemeStr(f"{verb} ", ThemeAttr("logview", "protocol")),
            ThemeStr(address1, ThemeAttr("logview", "uri")),
            ThemeStr(f" {protocol}", ThemeAttr("logview", "protocol")),
            ThemeStr("\" ", ThemeAttr("logview", "severity_info")),
            ThemeStr(statuscode, ThemeAttr("logview", severity_name)),
            ThemeStr(f" {number0}", ThemeAttr("logview", "severity_info")),
            ThemeStr(f" {number1}", ThemeAttr("logview", "severity_info")),
            ThemeStr(f" {number2}", ThemeAttr("logview", "severity_info")),
            ThemeStr(f" {number3}", ThemeAttr("logview", "severity_info")),
            ThemeStr(f" {number4} \"", ThemeAttr("logview", "severity_info")),
            ThemeStr(f"{client}", ThemeAttr("logview", "uri")),
            ThemeStr("\" \"", ThemeAttr("logview", "severity_info")),
            ThemeStr(str0, ThemeAttr("logview", "uri")),
            ThemeStr("\" \"", ThemeAttr("logview", "severity_info")),
            ThemeStr(str1, ThemeAttr("logview", "uri")),
            ThemeStr("\" \"", ThemeAttr("logview", "severity_info")),
            ThemeStr(str2, ThemeAttr("logview", "uri")),
            ThemeStr("\" \"", ThemeAttr("logview", "severity_info")),
            ThemeStr(str3, ThemeAttr("logview", "uri")),
            ThemeStr("\"", ThemeAttr("logview", "severity_info")),
        ]
        return facility, severity, new_message

    if severity is None:
        severity = LogLevel.INFO
    severity_name = f"severity_{loglevel_to_name(severity).lower()}"

    return (facility, severity,
            format_address(ipaddress, selected=False)
            + [ThemeStr(f"{message}", ThemeAttr("logview", severity_name))])
