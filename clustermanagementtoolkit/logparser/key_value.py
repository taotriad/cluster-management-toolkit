# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any, cast

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.kubernetes_resources import event_reasons

from clustermanagementtoolkit.logparser.custom_override_severity import custom_override_severity
from clustermanagementtoolkit.logparser.format_key_value import format_key_value
from clustermanagementtoolkit.logparser.logparser_types import LogparserConfiguration
from clustermanagementtoolkit.logparser.str_to_severity import str_to_severity


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def key_value(message: str, **kwargs: Any) -> tuple[str, LogLevel, list[ThemeRef | ThemeStr] | str,
                                                    list[tuple[list[ThemeRef | ThemeStr],
                                                               LogLevel]]]:
    """
    Format a key=value message.

        Parameters:
            message (str): The string to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
                options (dict): Additional, rule specific, options
        Returns:
            (str, LogLevel, str|ThemeArray, [(ThemeArray, LogLevel)]):
                (str): The facility of the message
                (LogLevel): The LogLevel of the message
                (ThemeArray | str): The untouched or formatted message
                ([(ThemeArray, LogLevel)]):
                    (ThemeArray): The formatted strings of the remnant
                    (LogLevel): The severity of the remnant

    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    options: dict = deep_get(kwargs, DictPath("options"), {})

    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

    messages = deep_get(options, DictPath("message#keys"), ["msg"])
    errors = deep_get(options, DictPath("error#keys"), ["err", "error"])
    highlight_reason = deep_get(options, DictPath("severity#highlight_reason"), False)
    timestamps = deep_get(options, DictPath("timestamp#keys"), ["t", "ts", "time"])
    severities = deep_get(options, DictPath("severity#keys"), ["level", "lvl", "logLevel"])
    facilities = deep_get(options, DictPath("facility#keys"),
                          ["source", "subsys", "caller", "logger", "Topic"])
    versions = deep_get(options, DictPath("version#keys"), ["version"])
    allow_bare_keys: str = deep_get(options, DictPath("allow_bare_keys"), "")
    newlines: str = deep_get(options, DictPath("newlines"), "keep")
    is_event: bool = deep_get(options, DictPath("is_event"), False)

    if is_event not in options and "Event occurred" in message:
        is_event = True

    # Split all key=value pairs. Make sure not to process "=="
    key_value_regex = re.compile(r"^(.*?[^=])=($|[^=].*$)")
    tmp: list[str] | None = re.findall(r"(?:\".*?\"|\S)+", message.replace("\\\"", "<<<quote>>>"))

    # pylint: disable-next=too-many-nested-blocks
    if tmp:
        # First go through the list of matches and check that there is at least one
        # key=value pair; we do not allow *only* bare keys. While it could theoretically
        # occur, it leaves too much room for false positives.
        # Also check whether the last word ends with a period. In this case we'll assume
        # that this is an informational message rather than a key=value message.
        if message.endswith(".") or not any("=" in item for item in tmp):
            # Give up; this line cannot be parsed as a set of key=value
            return facility, severity, message, remnants

        d: dict = {}
        for item in tmp:
            re_tmp = key_value_regex.match(item)
            if re_tmp is None:
                # pylint: disable-next=too-many-boolean-expressions
                if not item.endswith(":") \
                        and allow_bare_keys == "all" \
                        or allow_bare_keys == "lowercase" and item.lower() == item \
                        or allow_bare_keys == "uppercase" and item.upper() == item \
                        or allow_bare_keys == "capitalize" and item.capitalize() == item:
                    if item not in d:
                        d[item] = None
                else:
                    # Give up; this line cannot be parsed as a set of key=value
                    # FIXME: we need to handle this when using key_value_with_leading_message
                    return facility, severity, message, remnants
            else:
                key = re_tmp[1]
                value = re_tmp[2].replace("<<<quote>>>", "\\\"")
                if key not in d:
                    if (quoted := value.startswith("\"") and value.endswith("\"")):
                        value = value[1:-1]
                    if newlines == "strip_trailing":
                        value = value.rstrip("\n")
                    if quoted:
                        value = f"\"{value}\""
                    d[key] = value
                else:
                    # Give up; this line cannot be parsed as a set of key=value
                    break
            # XXX: Instead of just giving up we should probably do something with the leftovers...

        if LogparserConfiguration.pop_ts:
            for _ts in timestamps:
                d.pop(_ts, None)
        level = deep_get_with_fallback(d, severities)
        if LogparserConfiguration.pop_severity:
            for _sev in severities:
                d.pop(_sev, None)
        if level is not None:
            severity = str_to_severity(level, default=severity)

        msg = deep_get_with_fallback(d, messages, "")
        if msg.startswith("\"") and msg.endswith("\""):
            msg = msg[1:-1]

        if facility == "":
            for _fac in facilities:
                # For now we only support single facilities.
                if (facility := deep_get(d, DictPath(_fac), "")):
                    break
        if LogparserConfiguration.pop_facility:
            for _fac in facilities:
                if isinstance(_fac, str):
                    d.pop(_fac, None)
                elif isinstance(_fac, dict):
                    # This is a list, since the order of the facilities matter when outputting;
                    # it does not matter when popping though.
                    for __fac in deep_get(_fac, DictPath("keys"), []):
                        if __fac == "":
                            continue

                        d.pop(__fac)

        msg_tmp = []

        # If we are extracting msg we always want msg first
        if LogparserConfiguration.msg_extract and msg:
            msg_tmp.append(msg)
            # Pop the first matching _msg
            for _msg in messages:
                if _msg in d:
                    d.pop(_msg, "")
                    break
            for key in errors:
                if (value := d.pop(key, "")):
                    msg_tmp.append(format_key_value(key, value, severity, error_keys=errors))
        else:
            if LogparserConfiguration.msg_first:
                if (msg := deep_get_with_fallback(d, messages, "")):
                    force_severity = False
                    if not any(key in errors for key in d):
                        force_severity = True
                    msg_tmp.append(format_key_value("msg", msg, severity,
                                                    force_severity=force_severity))
                # Pop the first matching _msg
                for _msg in messages:
                    if _msg in d:
                        d.pop(_msg, "")
                        break
                for key in errors:
                    if (value := d.pop(key, "")):
                        msg_tmp.append(format_key_value(key, value, severity))

        for d_key, d_value in d.items():
            if highlight_reason and d_key == "type":
                severity_ = severity
                if d_value.strip("\"") == "Normal":
                    severity_ = LogLevel.NOTICE
                elif d_value.strip("\"") == "Warning":
                    severity_ = LogLevel.WARNING
                msg_tmp.append(format_key_value(d_key, d_value,
                                                severity_, force_severity=True))
            elif highlight_reason and d_key == "reason":
                severity_name = f"severity_{loglevel_to_name(severity).lower()}"
                reason_format = deep_get(event_reasons, DictPath(d_value.strip("\"")),
                                         ThemeAttr("logview", severity_name))
                reasonarray: list[ThemeStr | ThemeRef] = []
                reasonarray.append(ThemeStr(d_key, ThemeAttr("types", "key")))
                reasonarray += [ThemeRef("separators", "keyvalue_log")]
                reasonarray.append(ThemeStr(d_value, reason_format))
                msg_tmp.append(reasonarray)
            elif d_key in versions:
                msg_tmp.append(format_key_value(d_key, d_value,
                                                LogLevel.NOTICE, force_severity=True))
            elif d_key in severities:
                msg_tmp.append(format_key_value(d_key, d_value,
                                                severity, force_severity=True))
            else:
                if is_event and d_key == "type":
                    severity_ = severity
                    if d_value.strip("\"") == "Normal":
                        severity_ = LogLevel.NOTICE
                    elif d_value.strip("\"") == "Warning":
                        severity_ = LogLevel.WARNING
                    msg_tmp.append(format_key_value(d_key, d_value,
                                                    severity_, force_severity=True))
                    severity = min(severity, severity_)
                elif is_event and d_key == "reason":
                    reason_format = deep_get(event_reasons, DictPath(d_value.strip("\"")))
                    msg_tmp.append(format_key_value(d_key, d_value, severity,
                                                    force_severity=True,
                                                    value_format=reason_format))
                else:
                    # If we got an error message and it's not overridden,
                    # override the default formatting; else only override
                    # the formatting if the severity changed.
                    severity_, d_value = \
                        custom_override_severity(d_value, LogLevel.DEFAULT, options=options)
                    if severity_ == LogLevel.DEFAULT and d_key in messages + errors:
                        severity_ = severity
                        force_severity = True
                    else:
                        force_severity = severity_ != severity
                    msg_tmp.append(format_key_value(d_key, cast(str, d_value), severity_,
                                                    force_severity=force_severity,
                                                    allow_bare_keys=allow_bare_keys))

        if msg_tmp:
            message = msg_tmp.pop(0)
        else:
            message = ""
        if msg_tmp:
            for line in msg_tmp:
                remnants.append((line, severity))

    if facility.startswith("\"") and facility.endswith("\""):
        facility = facility[1:-1]

    severity_str = f"severity_{loglevel_to_name(severity).lower()}"

    if not message and not remnants:
        return facility, severity, message, remnants

    if isinstance(message, str):
        new_message: list[ThemeRef | ThemeStr] = \
            [ThemeStr(message, ThemeAttr("logview", severity_str))]
    else:
        new_message = message

    return facility, severity, new_message, remnants
