#! /usr/bin/env python3

# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Generate statistics about view-files.
"""

import errno
from functools import reduce
import sys
from typing import Any
import yaml

PROGRAMNAME: str = "viewfile_info.py"
PROGRAMVERSION: str = "0.0.1"

WHITE = "\033[1;37m"
DIM_RED = "\033[0;31m"
BRIGHT_RED = "\033[1;31m"
BRIGHT_GREEN = "\033[1;32m"
RESET = "\033[0m"

rule_statistics: dict[str, Any] = {
    "listview": {
        "datagetter": {"FIXME": None},
        "listgetter": {},
        "listgetter_async": {},
        "infogetter": {},
        "shortcuts": {
            "action": {},
        },
    },
    "infoview": {
        "infopad": {
            "objgetter": {},
            "infogetter": {},
            "datagetter": {"FIXME": None},
        },
        "listpad": {
            "listgetter": {},
            "infogetter": {},
        },
        "logpad": {
            "infogetter": {},
            "formatter": {},
        },
        "shortcuts": {
            "widget": {},
            "action": {},
            "action_call": {},
            "itemgetter": {},
        },
    },
}


def deep_get(dictionary: Any, path: str, default: Any = None) -> Any:
    """
    Given a dictionary and a path into that dictionary, get the value.

        Parameters:
            dictionary (dict): The dict to get the value from
            path (str): A dict path
            default (Any): The value to return if the dictionary, path, or result is None
        Returns:
            (Any): The value from the path
    """
    if dictionary is None:
        return default
    if path is None or not path or not isinstance(path, str):
        return default
    result = reduce(lambda d,
                    key: d.get(key, default) if isinstance(d, dict) else default,
                    path.split("#"), dictionary)
    if result is None:
        result = default
    return result


# pylint: disable-next=too-many-branches,too-many-statements
def generate_statistics(file: str, parser_rules: list[dict[str, Any]]) -> None:
    """
    Generate statistics about a view-file.

        Parameters:
            file (str): The view-file being scanned
            parser_rules ([dict[str, Any]]): The rules of a parser-file
    """
    if "listview" in parser_rules:
        if (tmp := deep_get(parser_rules, "listview#listgetter")):
            if tmp not in deep_get(rule_statistics, "listview#listgetter"):
                rule_statistics["listview"]["listgetter"][tmp] = []
            rule_statistics["listview"]["listgetter"][tmp].append(file)
        if (tmp := deep_get(parser_rules, "listview#listgetter_async")):
            if tmp not in deep_get(rule_statistics, "listview#listgetter_async"):
                rule_statistics["listview"]["listgetter_async"][tmp] = []
            rule_statistics["listview"]["listgetter_async"][tmp].append(file)
        if (tmp := deep_get(parser_rules, "listview#infogetter")):
            if tmp not in deep_get(rule_statistics, "listview#infogetter"):
                rule_statistics["listview"]["infogetter"][tmp] = []
            rule_statistics["listview"]["infogetter"][tmp].append(file)
        if (tmp := deep_get(parser_rules, "listview#shortcuts", {})):
            for _key, d in tmp.items():
                if not d:
                    continue
                if (tmp2 := deep_get(d, "action")):
                    if tmp2 not in deep_get(rule_statistics, "listview#shortcuts#action"):
                        rule_statistics["listview"]["shortcuts"]["action"][tmp2] = []
                    rule_statistics["listview"]["shortcuts"]["action"][tmp2].append(file)

    if "infoview" in parser_rules:
        if (infopad := deep_get(parser_rules, "infoview#infopad")):
            if (tmp := deep_get(infopad, "infogetter")):
                if tmp not in deep_get(rule_statistics, "infoview#infopad#infogetter"):
                    rule_statistics["infoview"]["infopad"]["infogetter"][tmp] = []
                rule_statistics["infoview"]["infopad"]["infogetter"][tmp].append(file)
            if (tmp := infopad.get("objgetter")):
                if tmp not in deep_get(rule_statistics, "infoview#infopad#objgetter"):
                    rule_statistics["infoview"]["infopad"]["objgetter"][tmp] = []
                rule_statistics["infoview"]["infopad"]["objgetter"][tmp].append(file)

        if (listpad := deep_get(parser_rules, "infoview#listpad")):
            if (tmp := deep_get(listpad, "listgetter")):
                if tmp not in deep_get(rule_statistics, "infoview#listpad#listgetter"):
                    rule_statistics["infoview"]["listpad"]["listgetter"][tmp] = []
                rule_statistics["infoview"]["listpad"]["listgetter"][tmp].append(file)
            if (tmp := deep_get(listpad, "infogetter")):
                if tmp not in deep_get(rule_statistics, "infoview#listpad#infogetter"):
                    rule_statistics["infoview"]["listpad"]["infogetter"][tmp] = []
                rule_statistics["infoview"]["listpad"]["infogetter"][tmp].append(file)

        if (logpad := deep_get(parser_rules, "infoview#logpad")):
            if (tmp := logpad.get("infogetter")):
                if tmp not in deep_get(rule_statistics, "infoview#logpad#infogetter"):
                    rule_statistics["infoview"]["logpad"]["infogetter"][tmp] = []
                rule_statistics["infoview"]["logpad"]["infogetter"][tmp].append(file)
            if (tmp := logpad.get("infogetter_args", {}).get("formatter")):
                if tmp not in deep_get(rule_statistics, "infoview#logpad#formatter"):
                    rule_statistics["infoview"]["logpad"]["formatter"][tmp] = []
                rule_statistics["infoview"]["logpad"]["formatter"][tmp].append(file)

        if (tmp := deep_get(parser_rules, "infoview#shortcuts", {})):
            for _key, d in tmp.items():
                if not d:
                    continue
                if (action := deep_get(d, "action")):
                    if action not in deep_get(rule_statistics, "infoview#shortcuts#action"):
                        rule_statistics["infoview"]["shortcuts"]["action"][action] = []
                    rule_statistics["infoview"]["shortcuts"]["action"][action].append(file)
                if (action_call := deep_get(d, "action_call")):
                    if action not in deep_get(rule_statistics, "infoview#shortcuts#action_call"):
                        rule_statistics["infoview"]["shortcuts"]["action_call"][action_call] = []
                    rule_statistics["infoview"]["shortcuts"]["action_call"][action_call].append(file)  # noqa: E501 pylint: disable=line-too-long
                if (widget := deep_get(d, "widget")):
                    if action not in deep_get(rule_statistics, "infoview#shortcuts#widget"):
                        rule_statistics["infoview"]["shortcuts"]["widget"][widget] = []
                    rule_statistics["infoview"]["shortcuts"]["widget"][widget].append(file)
                if (itemgetter := deep_get(d, "widget_args#itemgetter")):
                    if action not in deep_get(rule_statistics, "infoview#shortcuts#itemgetter"):
                        rule_statistics["infoview"]["shortcuts"]["itemgetter"][itemgetter] = []
                    rule_statistics["infoview"]["shortcuts"]["itemgetter"][itemgetter].append(file)


def main() -> None:
    """
    Main function for the program.
    """
    verbose: bool = True

    if len(sys.argv) < 2:
        print(f"{PROGRAMNAME}: Missing argument.")
        sys.exit(errno.EINVAL)

    for file in sys.argv[1:]:
        try:
            with open(file, "r", encoding="utf-8") as f:
                try:
                    d = yaml.safe_load(f.read())
                    generate_statistics(file, d)
                except AttributeError:
                    print(f"Filename: {file}")
                    raise
        except FileNotFoundError:
            print(f"{DIM_RED}WARNING{RESET}: File {file} does not exist; skipping.\n")
            continue

    print(f"{WHITE}Note{RESET}: only explicitly defined rules are included\n")

    if verbose:
        print("rule: [users]")
        print("-------------")
        sys.exit(yaml.dump(rule_statistics, indent=2))
#       for rule, data in rule_statistics.items():
#           print(f"{WHITE}{rule}{RESET}: [{','.join(sorted(data))}]")
#       print()

    print("Summary:")
    for rule, data in rule_statistics.items():
        print(f"{WHITE}{rule:>30}{RESET}: {len(data)}")


if __name__ == "__main__":
    main()
