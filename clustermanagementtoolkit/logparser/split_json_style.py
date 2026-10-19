# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import ast
import json
from typing import Any, cast

from clustermanagementtoolkit.cmtio_yaml import json_dumps
from clustermanagementtoolkit.cmtio_yaml import json_loads

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit import formatters

from clustermanagementtoolkit.logparser.custom_override_severity import custom_override_severity
from clustermanagementtoolkit.logparser.fold_message_with_remnants import fold_message_with_remnants
from clustermanagementtoolkit.logparser.logparser_types import LogparserConfiguration
from clustermanagementtoolkit.logparser.str_to_severity import str_to_severity


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def split_json_style(message: str, **kwargs: Any) \
    -> tuple[str, LogLevel, list[ThemeRef | ThemeStr] | str,
             list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Split JSON style messages.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
                fold_msg (bool): [unused]
                options (dict): Additional, rule specific, options
        Returns:
            (str, LogLevel, str|ThemeArray, [(ThemeArray, LogLevel)]):
                (str): The facility of the message
                (LogLevel): The LogLevel of the message
                (str|ThemeArray): The untouched or formatted message
                ([(ThemeArray, LogLevel)]):
                    (ThemeArray): The formatted strings of the remnant
                    (LogLevel): The severity of the remnant
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)
    options: dict = deep_get(kwargs, DictPath("options"), {})
    logentry: dict = {}

    messages: list[DictPath] = deep_get(options, DictPath("message#keys"),
                                        ["msg", "message", "Message", "@message"])
    errors: list[DictPath] = deep_get(options, DictPath("error#keys"), ["err", "Err", "error"])
    error_tags = deep_get(options, DictPath("error#tags"), {})
    timestamps: list[DictPath] = deep_get(options, DictPath("timestamp#keys"),
                                          ["ts", "time", "Time", "timestamp", "@timestamp"])
    severities: list[DictPath] = deep_get(options, DictPath("severity#keys"),
                                          ["level", "Level", "@level"])
    facilities: list[DictPath] = deep_get(options,
                                          DictPath("facility#keys"),
                                          ["logger", "caller", "filename"])
    versions: list[DictPath] = deep_get(options, DictPath("version#keys"),
                                        ["version", "Version"])

    message = message.replace("\x00", "")

    try:
        logentry = cast(dict, json_loads(message))
    except (ValueError, json.decoder.JSONDecodeError):
        pass

    # Unfold Python dicts
    if logentry is None:
        d = None
        try:
            d = ast.literal_eval(message)
        except (ValueError, TypeError, SyntaxError, RecursionError):
            pass

        if d is not None:
            try:
                logentry = json_dumps(d)
            except (ValueError, json.decoder.JSONDecodeError):
                pass

    # pylint: disable-next=too-many-nested-blocks
    if isinstance(logentry, dict):
        # If msg_first we reorder the dict
        if LogparserConfiguration.msg_first:
            _d = {}
            for key in messages + errors:
                value = deep_get(logentry, DictPath(key), None)
                if value is not None:
                    _d[key] = value
            for key in logentry:
                if key not in messages + errors:
                    value = deep_get(logentry, DictPath(key), "")
                    if value is not None:
                        _d[key] = value
            logentry = _d

        msg = deep_get_with_fallback(logentry, messages, "")
        level = deep_get_with_fallback(logentry, severities, None)
        if LogparserConfiguration.pop_severity:
            for _sev in severities:
                logentry.pop(_sev, None)
        if LogparserConfiguration.pop_ts:
            for _ts in timestamps:
                logentry.pop(_ts, None)

        if facility == "":
            for _fac in facilities:
                if isinstance(_fac, str):
                    facility = deep_get(logentry, DictPath(_fac), "")
                    break

                if not isinstance(_fac, dict):
                    continue

                _facilities = deep_get(_fac, DictPath("keys"), [])
                _separators = deep_get(_fac, DictPath("separators"), [])
                for i, _fac in enumerate(_facilities):
                    # This is to allow prefixes/suffixes.
                    if _fac != "":
                        if _fac not in logentry:
                            break
                        facility += str(deep_get(logentry, DictPath(_fac), ""))
                    if i < len(_separators):
                        facility += _separators[i]

        if LogparserConfiguration.pop_facility:
            for _fac in facilities:
                if isinstance(_fac, str):
                    logentry.pop(_fac, None)
                if not isinstance(_fac, dict):
                    continue
                # This is a list, since the order of the facilities matter when outputting
                # it does not matter when popping though
                for __fac in deep_get(_fac, DictPath("keys"), []):
                    if __fac == "":
                        continue

                    logentry.pop(__fac, None)

        if level is not None:
            severity = str_to_severity(level)

        if severity is not None and severity == LogLevel.DEBUG:
            structseverity: LogLevel = severity
        else:
            structseverity = LogLevel.INFO

        if "err" not in logentry and "error" not in logentry:
            if severity is not None:
                msgseverity = severity
            else:
                msgseverity = LogLevel.INFO
        else:
            msgseverity = structseverity
        if severity is not None:
            errorseverity = severity
        else:
            errorseverity = LogLevel.ERR

        if LogparserConfiguration.msg_extract:
            message = msg
            # Pop the first matching _msg
            for _msg in messages:
                if _msg in logentry:
                    logentry.pop(_msg, None)
                    break
        else:
            message = ""

        override_formatting: dict[str, Any] = {}
        formatted_message = None
        remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

        if logentry:
            tagseverity = None
            if structseverity == LogLevel.DEBUG:
                override_formatting = {"__all": ThemeAttr("logview", "severity_debug")}
            else:
                for _msg in versions:
                    override_formatting[f"\"{_msg}\""] = {
                        "key": ThemeAttr("types", "yaml_key"),
                        "value": ThemeAttr("logview", "severity_notice")
                    }
                msg_severity_name = f"severity_{loglevel_to_name(msgseverity).lower()}"
                error_severity_name = f"severity_{loglevel_to_name(errorseverity).lower()}"
                for _msg in messages:
                    override_formatting[f"\"{_msg}\""] = {
                        "key": ThemeAttr("types", "yaml_key"),
                        "value": ThemeAttr("logview", msg_severity_name)
                    }
                for _err in errors:
                    override_formatting[f"\"{_err}\""] = {
                        "key": ThemeAttr("types", "yaml_key_error"),
                        "value": ThemeAttr("logview", error_severity_name),
                    }
                for tag, tag_values in error_tags.items():
                    for tag_key, tag_severity in tag_values.items():
                        if tag_key in deep_get(logentry, DictPath(tag), []):
                            tagseverity = str_to_severity(tag_severity, default=msgseverity)
                            break
                    if tagseverity is not None:
                        break
                for d_key in messages + errors:
                    d_value = deep_get(logentry, DictPath(d_key), "")
                    if not d_value:
                        continue
                    d_severity, d_value = \
                        custom_override_severity(d_value, LogLevel.DEFAULT, options=options)
                    if d_severity == LogLevel.DEFAULT:
                        continue
                    override_severity_name = f"severity_{loglevel_to_name(d_severity).lower()}"
                    if d_severity == LogLevel.DEBUG:
                        override_formatting = {"__all": ThemeAttr("logview", "severity_debug")}
                    elif d_key in errors:
                        override_formatting[f"\"{d_key}\""] = {
                            "key": ThemeAttr("types", "yaml_key_error"),
                            "value": ThemeAttr("logview", override_severity_name),
                        }
                    else:
                        override_formatting[f"\"{d_key}\""] = {
                            "key": ThemeAttr("types", "yaml_key"),
                            "value": ThemeAttr("logview", override_severity_name),
                        }
                    severity = d_severity
                    tagseverity = None
            if tagseverity is not None:
                tag_severity_name = f"severity_{loglevel_to_name(tagseverity).lower()}"
                override_formatting[f"\"{_msg}\""] = {
                    "key": ThemeAttr("types", "yaml_key"),
                    "value": ThemeAttr("logview", tag_severity_name)
                }
                severity = tagseverity

            dump = json_dumps(logentry)

            tmp = formatters.format_yaml([dump], override_formatting=override_formatting, json=True)

            if severity is None:
                if structseverity is not None:
                    severity = structseverity
                else:
                    severity = LogLevel.INFO
            if not message:
                formatted_message = tmp[0]
                tmp.pop(0)
                msgseverity = structseverity
            for line in tmp:
                remnants.append((line, severity))

        if formatted_message is not None:
            if fold_msg:
                formatted_message = \
                    fold_message_with_remnants(formatted_message, remnants, severity)
                remnants = []

            return facility, severity, formatted_message, remnants

        if isinstance(message, str):
            _severity, _message = \
                custom_override_severity(message, severity, options=options)

    return facility, severity, message, []
