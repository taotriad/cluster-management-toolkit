#! /usr/bin/env python3

# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Generate statistics about view-files.
"""

import errno
import sys
from typing import Any
import yaml

PROGRAMNAME: str = "viewfile_info.py"
PROGRAMVERSION: str = "0.0.1"

WHITE = "\033[1;37m"
DIM_RED = "\033[0;31m"
BRIGHT_RED = "\033[1;31m"
BRIGHT_GREEN= "\033[1;32m"
RESET = "\033[0m"

rule_statistics: dict[str, list[str]] = {
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


def generate_statistics(file: str, parser_rules: list[dict[str, Any]]) -> None:
    """
    Generate statistics about a view-file.

        Parameters:
            file (str): The view-file being scanned
            parser_rules ([dict[str, Any]]): The rules of a parser-file
    """
    if "listview" in parser_rules:
        if (tmp := parser_rules.get("listview", {}).get("listgetter")):
            if tmp not in rule_statistics["listview"]["listgetter"]:
                rule_statistics["listview"]["listgetter"][tmp] = []
            rule_statistics["listview"]["listgetter"][tmp].append(file)
        if (tmp := parser_rules.get("listview", {}).get("listgetter_async")):
            if tmp not in rule_statistics["listview"]["listgetter_async"]:
                rule_statistics["listview"]["listgetter_async"][tmp] = []
            rule_statistics["listview"]["listgetter_async"][tmp].append(file)
        if (tmp := parser_rules.get("listview", {}).get("infogetter")):
            if tmp not in rule_statistics["listview"]["infogetter"]:
                rule_statistics["listview"]["infogetter"][tmp] = []
            rule_statistics["listview"]["infogetter"][tmp].append(file)
        if (tmp := parser_rules.get("listview", {}).get("shortcuts", {})):
            for key, d in tmp.items():
                if not d:
                    continue
                if (tmp2 := d.get("action")):
                    if tmp2 not in rule_statistics["listview"]["shortcuts"]["action"]:
                        rule_statistics["listview"]["shortcuts"]["action"][tmp2] = []
                    rule_statistics["listview"]["shortcuts"]["action"][tmp2].append(file)

    if "infoview" in parser_rules:
        infopad = parser_rules.get("infoview", {}).get("infopad")
        if infopad:
            if (tmp := infopad.get("infogetter")):
                if tmp not in rule_statistics["infoview"]["infopad"]["infogetter"]:
                    rule_statistics["infoview"]["infopad"]["infogetter"][tmp] = []
                rule_statistics["infoview"]["infopad"]["infogetter"][tmp].append(file)
            if (tmp := infopad.get("objgetter")):
                if tmp not in rule_statistics["infoview"]["infopad"]["objgetter"]:
                    rule_statistics["infoview"]["infopad"]["objgetter"][tmp] = []
                rule_statistics["infoview"]["infopad"]["objgetter"][tmp].append(file)

        listpad = parser_rules.get("infoview", {}).get("listpad")
        if listpad:
            if (tmp := listpad.get("listgetter")):
                if tmp not in rule_statistics["infoview"]["listpad"]["listgetter"]:
                    rule_statistics["infoview"]["listpad"]["listgetter"][tmp] = []
                rule_statistics["infoview"]["listpad"]["listgetter"][tmp].append(file)
            if (tmp := listpad.get("infogetter")):
                if tmp not in rule_statistics["infoview"]["listpad"]["infogetter"]:
                    rule_statistics["infoview"]["listpad"]["infogetter"][tmp] = []
                rule_statistics["infoview"]["listpad"]["infogetter"][tmp].append(file)

        logpad = parser_rules.get("infoview", {}).get("logpad")
        if logpad:
            if (tmp := logpad.get("infogetter")):
                if tmp not in rule_statistics["infoview"]["logpad"]["infogetter"]:
                    rule_statistics["infoview"]["logpad"]["infogetter"][tmp] = []
                rule_statistics["infoview"]["logpad"]["infogetter"][tmp].append(file)
            if (tmp := logpad.get("infogetter_args", {}).get("formatter")):
                if tmp not in rule_statistics["infoview"]["logpad"]["formatter"]:
                    rule_statistics["infoview"]["logpad"]["formatter"][tmp] = []
                rule_statistics["infoview"]["logpad"]["formatter"][tmp].append(file)

        if (tmp := parser_rules.get("infoview", {}).get("shortcuts", {})):
            for key, d in tmp.items():
                if not d:
                    continue
                if (action := d.get("action")):
                    if action not in rule_statistics["infoview"]["shortcuts"]["action"]:
                        rule_statistics["infoview"]["shortcuts"]["action"][action] = []
                    rule_statistics["infoview"]["shortcuts"]["action"][action].append(file)
                if (action_call := d.get("action_call")):
                    if action_call not in rule_statistics["infoview"]["shortcuts"]["action_call"]:
                        rule_statistics["infoview"]["shortcuts"]["action_call"][action_call] = []
                    rule_statistics["infoview"]["shortcuts"]["action_call"][action_call].append(file)
                if (widget := d.get("widget")):
                    if widget not in rule_statistics["infoview"]["shortcuts"]["widget"]:
                        rule_statistics["infoview"]["shortcuts"]["widget"][widget] = []
                    rule_statistics["infoview"]["shortcuts"]["widget"][widget].append(file)
                if (itemgetter := d.get("widget_args", {}).get("itemgetter", {})):
                    if itemgetter not in rule_statistics["infoview"]["shortcuts"]["itemgetter"]:
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
