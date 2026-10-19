# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from datetime import datetime
import sys
from typing import Any

try:
    import ruyaml  # type: ignore[import-not-found,unused-ignore]
    ryaml = ruyaml.YAML()
    sryaml = ruyaml.YAML(typ="safe")
except ModuleNotFoundError:  # pragma: no cover
    try:
        import ruamel.yaml as ruyaml  # type: ignore[no-redef,unused-ignore]
        ryaml = ruyaml.YAML()
        sryaml = ruyaml.YAML(typ="safe")
    except ModuleNotFoundError:  # pragma: no cover
        sys.exit("ModuleNotFoundError: Could not import ruyaml/ruamel.yaml; "
                 "you may need to (re-)run `cmt-install.py` or `pip3 install ruyaml/ruamel.yaml`; "
                 "aborting.")

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmtlib import none_timestamp
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import name_to_loglevel

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_len


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_cmt_log(obj: dict, **kwargs: Any) -> \
        tuple[list[datetime], list[str | tuple[list[ThemeRef | ThemeStr], str]], list[LogLevel],
              list[list[ThemeRef | ThemeStr] | str]]:
    """
    Extract log entries from CMT log.

        Parameters:
            obj (dict): The object to extract log entries from
            **kwargs (dict[str, Any]): Keyword arguments
                severity_prefixes (str): Prefix every message with the severity;
                                         useful when using a limited terminal,
                                         for use with CVD, etc.
                filepath (str): The path to the file to read log messages from
        Returns:
            (([str], [str], [str], [str])):
                ([datetime]): A list of formatted timestamps
                ([str|(str, str)]): A list of facilities
                ([LogLevel]): A list of severities
                ([ThemeArray]): A list of ThemeArrays
    """
    filepath = deep_get(obj, DictPath("filepath"), "")
    severity_prefixes = deep_get(kwargs, DictPath("severity_prefixes"), False)
    timestamps: list[datetime] = []
    facilities: list[tuple[list[ThemeRef | ThemeStr], str] | str] = []
    severities: list[LogLevel] = []
    messages: list[list[ThemeRef | ThemeStr] | str] = []

    d = []

    try:
        if (tmp := secure_read_yaml(filepath)) is not None:
            d = list(tmp)
    except FileNotFoundError:
        pass
    except (TypeError, ruyaml.scanner.ScannerError) as e:
        return ([], ["secure_read_yaml()"], [LogLevel.ERR],
                [[ThemeStr(f"{e}", ThemeAttr("types", "generic"))]])

    if not d or not isinstance(d, list):
        return timestamps, facilities, severities, messages

    for message in d:
        timestamp = deep_get(message, DictPath("timestamp"), "")
        severitystr = deep_get(message, DictPath("severity"), "")
        severity = name_to_loglevel(severitystr)
        facility = deep_get(message, DictPath("facility"), "<unknown>")
        file = deep_get(message, DictPath("file"), "")
        function = deep_get(message, DictPath("function"), "")
        lineno = deep_get(message, DictPath("lineno"), "")

        facilityarray: list[ThemeRef | ThemeStr] = [
            ThemeStr(f"{file}", ThemeAttr("types", "path")),
            ThemeStr(":", ThemeAttr("types", "separator")),
            ThemeStr(f"{lineno}", ThemeAttr("types", "lineno")),
            ThemeStr("|", ThemeAttr("types", "separator")),
            ThemeStr(f"{function}()", ThemeAttr("types", "python_function")),
        ]

        themestrings = True
        msgs = deep_get(message, DictPath("themearray"), [])
        if not msgs:
            themestrings = False
            msgs = deep_get(message, DictPath("strarray"), [])

        first = True

        d_timestamp = timestamp_to_datetime(timestamp)
        for msg in msgs:
            if first:
                timestamps.append(d_timestamp.astimezone())
                facilities.append((facilityarray, facility))
                first = False
            else:
                timestamps.append(none_timestamp())
                facilitypad = "".ljust(themearray_len(facilityarray))
                facilitypadarray: list[ThemeRef | ThemeStr] = \
                    [ThemeStr(facilitypad, ThemeAttr("types", "generic"))]
                facilities.append((facilitypadarray + facilityarray, "".ljust(len(facility))))
            severities.append(severity)

            reformatted_msg: list[ThemeRef | ThemeStr] = []
            for substring in msg:
                if themestrings:
                    # These log messages are in ANSIThemeStr format;
                    # hence we need to convert them to ThemeStrs.
                    # Luckily ANSIThemeStr has fewer formats
                    # than ThemeStr. We should probably have
                    # a cross-reference table in themes though.
                    string = deep_get(substring, DictPath("string"))
                    themeref = deep_get(substring, DictPath("themeref"))
                else:
                    string = substring
                    themeref = "default"
                fmt = None
                if themeref == "default":
                    # When prepending the severity in front of the message we do not need to
                    # highlight the text, otherwise we use the severity as highlight colour.
                    if severity_prefixes:
                        fmt = ThemeAttr("main", "default")
                    else:
                        themeref = severitystr.lower()
                elif themeref == "emphasis":
                    fmt = ThemeAttr("main", "highlight")
                elif themeref in ("path", "hostname", "programname", "errorvalue", "separator"):
                    fmt = ThemeAttr("types", themeref)
                elif themeref == "argument":
                    fmt = ThemeAttr("main", "infoheader")
                if themeref in ("debug", "info", "warning", "error", "critical"):
                    fmt = ThemeAttr("logview", f"severity_{themeref}")
                if fmt is None:
                    fmt = ThemeAttr("main", "default")
                reformatted_msg.append(ThemeStr(string, fmt))
            messages.append(reformatted_msg)

    return timestamps, facilities, severities, messages
