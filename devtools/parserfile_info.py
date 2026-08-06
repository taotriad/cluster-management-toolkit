#! /usr/bin/env python3

# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Generate statistics about parser-files.
"""

import errno
import sys
from typing import Any
import yaml

PROGRAMNAME: str = "parserfile_info.py"
PROGRAMVERSION: str = "0.0.1"

WHITE = "\033[1;37m"
RESET = "\033[0m"

rule_statistics: dict[str, list[str]] = {}


def generate_statistics(file: str, parser_rules: list[dict[str, Any]]) -> None:
    """
    Generate statistics about a parser-file.

        Parameters:
            file (str): The parser-file being scanned
            parser_rules ([dict[str, Any]]): The rules of a parser-file
    """
    for ruleset in parser_rules:
        try:
            rulesetname = ruleset["name"]
        except KeyError:
            print(f"Warning: parser-file {file} has a ruleset without a name; skipping.")
            continue
        except TypeError:
            continue

        for rule in ruleset.get("parser_rules", {}):
            try:
                rulename = rule["name"]
            except KeyError:
                print(f"Warning: parser-file {file}, "
                      f"ruleset {rulesetname} has a rule without a name; skipping.")
                continue
            if rulename not in rule_statistics:
                rule_statistics[rulename] = []
            rule_statistics[rulename].append(file)


def main() -> None:
    """
    Main function for the program.
    """
    verbose: bool = True

    if len(sys.argv) < 2:
        print(f"{PROGRAMNAME}: Missing argument.")
        sys.exit(errno.EINVAL)

    for file in sys.argv[1:]:
        with open(file, "r", encoding="utf-8") as f:
            try:
                d = yaml.safe_load(f.read())
                generate_statistics(file, d)
            except FileNotFoundError:
                print(f"File {file} does not exist; skipping.")
                continue

    if verbose:
        print("rule: [users]")
        print("-------------")
        for rule, data in rule_statistics.items():
            print(f"{WHITE}{rule}{RESET}: [{','.join(sorted(data))}]")
        print()

    print("Summary:")
    for rule, data in rule_statistics.items():
        print(f"{WHITE}{rule:>30}{RESET}: {len(data)}")


if __name__ == "__main__":
    main()
