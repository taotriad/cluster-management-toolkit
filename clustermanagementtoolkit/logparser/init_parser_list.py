# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from pathlib import Path
import re
import sys
from typing import Any, cast, Literal

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

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

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml
from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml_all

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmtpaths import HOMEDIR
from clustermanagementtoolkit.cmtpaths import PARSERS_DIR
from clustermanagementtoolkit.cmtpaths import SYSTEM_PARSERS_DIR

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.logparser.compile_override_rules import compile_override_rules
from clustermanagementtoolkit.logparser import logparser_types
from clustermanagementtoolkit.logparser.logparser_types import LogparserConfiguration
from clustermanagementtoolkit.logparser.logparser_types import MatchRule
from clustermanagementtoolkit.logparser.logparser_types import Parser
from clustermanagementtoolkit.logparser.logparser_types import ParserRule


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def init_parser_list(force_reinit: bool = False) -> None:
    """
    Initialise the list of parsers.

        Parameters:
            force_reinit (bool): Force the parser-list to be re-read.
    """
    if force_reinit:
        logparser_types.parsers = []

    # Get a full list of parsers from all parser directories
    # Start by adding files from the parsers directory.

    parser_dirs = []
    parser_dirs += deep_get(cmtlib.cmtconfig, DictPath("Pod#local_parsers"), [])
    parser_dirs.append(PARSERS_DIR)
    parser_dirs.append(SYSTEM_PARSERS_DIR)

    parser_files = []

    for parser_dir in parser_dirs:
        if parser_dir.startswith("{HOME}"):
            parser_dir = parser_dir.replace("{HOME}", HOMEDIR, 1)

        if not Path(parser_dir).is_dir():
            continue

        parser_dir = FilePath(parser_dir)

        if Path(parser_dir).joinpath("BUNDLE.yaml").is_file():
            path = FilePath(parser_dir).joinpath("BUNDLE.yaml")
            parser_files.append(path)
            continue

        for ppath in cast(list[Path], natsorted(Path(parser_dir).iterdir())):
            filename = ppath.name

            if filename.startswith(("~", ".")) \
                    or not filename.endswith((".yaml", ".yml")) \
                    or filename.endswith("configmaps.yaml"):

                continue

            parser_files.append(FilePath(ppath))

    for parser_file in parser_files:
        if parser_file.endswith("BUNDLE.yaml"):
            temp_dl = secure_read_yaml_all(parser_file,
                                           directory_is_symlink=True, asynchronous=True)
            try:
                dl = [list(d) for d in temp_dl]
            except (ruyaml.composer.ComposerError,
                    ruyaml.constructor.DuplicateKeyError,
                    ruyaml.parser.ParserError,
                    ruyaml.scanner.ScannerError,
                    TypeError) as e:
                errmsg = [
                    [("Failed to load parser-file ", "default"),
                     (f"{parser_file}", "path"),
                     (f": {type(e)}", "errorvalue"),
                     ("; skipping.", "path")],
                ]
                errmsg_with_event = [
                    [("Failed to load parser-file ", "default"),
                     (f"{parser_file}", "path"),
                     (f": {type(e)}", "errorvalue")],
                ]
                for line in str(e).splitlines():
                    errmsg_with_event.append([(line.replace('"', '\\\"'), "default")])
                unformatted_msg, _formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                _unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg_with_event)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                continue
            LogparserConfiguration.using_bundles = True
        else:
            try:
                d = list(secure_read_yaml(parser_file,
                                          directory_is_symlink=True, asynchronous=True))
            except (ruyaml.composer.ComposerError,
                    ruyaml.constructor.DuplicateKeyError,
                    ruyaml.parser.ParserError,
                    ruyaml.scanner.ScannerError,
                    TypeError) as e:
                errmsg = [
                    [("Failed to load parser-file ", "default"),
                     (f"{parser_file}", "path"),
                     (f": {type(e)}", "errorvalue"),
                     ("; skipping.", "path")],
                ]
                errmsg_with_event = [
                    [("Failed to load parser-file ", "default"),
                     (f"{parser_file}", "path"),
                     (f": {type(e)}", "errorvalue")],
                ]
                for line in str(e).splitlines():
                    errmsg_with_event.append([(line.replace('"', '\\\"'), "default")])
                unformatted_msg, _formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                _unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg_with_event)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                continue
            dl = [d]

        # pylint: disable-next=too-many-nested-blocks
        for parser_dict in dl:
            for parser in parser_dict:
                parser_name = deep_get(parser, DictPath("name"), "")
                if not parser_name:
                    continue
                show_in_selector = deep_get(parser, DictPath("show_in_selector"), False)
                matchrules: list[MatchRule] = []
                for matchkey in deep_get(parser, DictPath("matchkeys")):
                    pod_name = deep_get(matchkey, DictPath("pod_name"), "")
                    container_name = deep_get(matchkey, DictPath("container_name"), "")
                    image_name = deep_get(matchkey, DictPath("image_name"), "")
                    image_regex_raw = deep_get(matchkey, DictPath("image_regex"), "")
                    if image_regex_raw:
                        image_regex: re.Pattern | None = re.compile(image_regex_raw)
                    else:
                        image_regex = None
                    container_type: Literal["Container", "InitContainer"] = \
                        deep_get(matchkey, DictPath("container_type"), "Container")
                    # We need at least one way of matching
                    if not any((pod_name, container_name, image_name, image_regex)):
                        continue
                    matchrule: MatchRule = \
                        MatchRule(pod_name, container_name, image_name, container_type, image_regex)
                    matchrules.append(matchrule)

                if not matchrules:
                    continue

                parser_rules = deep_get(parser, DictPath("parser_rules"))
                if not parser_rules:
                    continue

                rules: list[ParserRule] = []

                for rule in parser_rules:
                    overrides: list[dict[str, Any]] = []

                    rule_name = deep_get(rule, DictPath("name"))
                    if rule_name in ("bracketed_severity",
                                     "custom_line",
                                     "custom_splitter",
                                     "directory",
                                     "expand_event",
                                     "glog",
                                     "http",
                                     "iptables",
                                     "json",
                                     "json_event",
                                     "json_with_leading_message",
                                     "key_value",
                                     "key_value_with_leading_message",
                                     "modinfo",
                                     "override_severity",
                                     "seconds_severity_facility",
                                     "strip_ansicodes",
                                     "sysctl",
                                     "tab_separated",
                                     "ts_8601"):

                        options = deep_get(rule, DictPath("options"), {})

                        for key, value in options.items():
                            if key in ("block_start", "block_end"):
                                tmp = []
                                for entry in value:
                                    if deep_get(entry, DictPath("matchtype"), "") \
                                            in ("match", "regex", "search"):
                                        regex = deep_get(entry, DictPath("matchkey"), "")
                                        if regex is not None:
                                            compiled_regex = re.compile(regex)
                                            entry["matchkey"] = compiled_regex
                                    tmp.append(entry)
                            elif key in ("match", "regex", "search"):
                                # Regular expressions:
                                # search will use re.search()
                                # match will use re.match()
                                # regex is retained for backwards compatibility
                                # and will use re.match()
                                regex = deep_get(rule, DictPath("options#regex"), "")
                                value = re.compile(regex)
                            elif key == "severity":
                                value = deep_get(rule, DictPath("options#severity"), {})
                                overrides = deep_get(value, DictPath("overrides"), [])
                                if overrides:
                                    value["overrides"] = \
                                        compile_override_rules(parser_file, overrides)
                            options[key] = value
                        rules.append(ParserRule(rule_name, options))
                    else:
                        errmsg = [
                            [("Parser-file ", "default"),
                             (f"{parser_file}", "path"),
                             (" has an unknown rule-type ", "default"),
                             (f"{rule_name}", "argument"),
                             ("; ignoring parser-file.", "default")],
                        ]
                        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                        continue

                logparser_types.parsers.append(Parser(name=parser_name,
                                                      show_in_selector=show_in_selector,
                                                      match=matchrules, rules=rules))

    # Fallback entries
    logparser_types.parsers.append(Parser(name="basic_8601_raw", show_in_selector=True,
                                          match=[MatchRule("raw", "", "", "Container", None)],
                                          rules=[]))
    # This should always be last
    logparser_types.parsers.append(Parser(name="basic_8601", show_in_selector=True,
                                          match=[MatchRule("raw", "", "", "Container", None)],
                                          rules=[ParserRule("ts_8601", {})]))
