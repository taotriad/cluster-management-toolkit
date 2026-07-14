#! /usr/bin/env python3

# Requires: python3 (>= 3.11)

# Copyright David Weinehall
# SPDX-License-Identifier: MIT

"""
This program creates a table of content for Markdown documents.
"""

import errno
import sys
from typing import NoReturn

PROGRAMNAME: str = "mdtoc.py"
PROGRAMVERSION: str = "v0.0.1"

PROGRAMDESCRIPTION: str = "Generate a table of contents from a list of Markdown files"
PROGRAMAUTHORS: str = "Written by David Weinehall."

COPYRIGHT: str = "Copyright © 2026 David Weinehall"

LICENSE: str = "This is free software; see the source for copying conditions.  There is NO\n" \
               "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."

DEFAULT_DEPTH: int = 3


def usage() -> NoReturn:
    """
    Display usage information.
    """
    print(f"{PROGRAMNAME} FILE...")
    print()
    print(PROGRAMDESCRIPTION)
    print()
    print("Options:")
    print("  --depth DEPTH     How many header levels should be included [2-4]")
    print("  --no-toc-header   Do not output the Table of Contents header")
    print("  --split-sections  Should level 1 headers start new lists?")
    print()
    print("help|--help         Display this help and exit")
    print("version|--version   Output version information and exit")

    sys.exit(0)


def version() -> NoReturn:
    """
    Display version information.
    """
    print(f"{PROGRAMNAME} {PROGRAMVERSION}")
    print()
    print(COPYRIGHT)
    print(LICENSE)
    print()
    print(PROGRAMAUTHORS)

    sys.exit(0)


# pylint: disable-next=too-many-branches,too-many-statements
def main() -> None:
    """
    Main function for the program.
    """
    if len(sys.argv) == 1:
        print(f"{PROGRAMNAME}: Missing operand.")
        print(f"Try \"{PROGRAMNAME} --help\" for more information.")
        sys.exit(errno.EINVAL)

    depth: int = DEFAULT_DEPTH
    split_sections: bool = False
    base_indent: str = "    "
    toc_header: bool = True
    i: int = 1

    while i < len(sys.argv):
        if sys.argv[i] in ("--help", "help"):
            usage()
        if sys.argv[i] in ("--version", "version"):
            version()
        if sys.argv[i] == "--depth":
            if i + 1 < len(sys.argv):
                i += 1
            try:
                depth = int(sys.argv[i])
            except ValueError:
                print(f"{PROGRAMNAME} “--depth DEPTH“ requires an integer argument",
                      file=sys.stderr)
                print("Try “{PROGRAMNAME} help“ for more information.", file=sys.stderr)
                sys.exit(errno.EINVAL)
            if not 1 < depth < 5:
                print(f"{PROGRAMNAME} “--depth DEPTH“ must be in the range [2-4]", file=sys.stderr)
                print("Try “{PROGRAMNAME} help“ for more information.", file=sys.stderr)
                sys.exit(errno.EINVAL)
            i += 1
            continue
        if sys.argv[i] == "--no-toc-header":
            toc_header = False
            i += 1
            continue
        if sys.argv[i] == "--split-sections":
            split_sections = True
            base_indent = ""
            i += 1
            continue
        break

    if i >= len(sys.argv):
        print(f"{PROGRAMNAME}: Missing operand.")
        print(f"Try \"{PROGRAMNAME} --help\" for more information.")
        sys.exit(errno.EINVAL)

    indices: list[int] = [0, 0, 0, 0]

    # Print the document header
    if toc_header:
        print("# Table of Contents\n")

    for filename in sys.argv[i:]:
        with open(f"{filename}", "r", encoding="utf-8") as f:
            tmp = f.read()

        prefix: str = ""
        indent: str = ""
        index: str = ""

        # Note: We only index the first three levels
        for line in tmp.splitlines():
            if not line.startswith("#"):
                continue

            # Level 1 header
            if line.startswith("# "):
                prefix = "# "
                index = indices[0] = indices[0] + 1
                indices[1] = 0
                indices[2] = 0
                indent = ""

            # Level 2 header
            if line.startswith("## "):
                prefix = "## "
                index = indices[1] = indices[1] + 1
                indices[2] = 0
                indent = f"{base_indent}"

            # Level 3 header
            if line.startswith("### "):
                if depth < 3:
                    continue
                prefix = "### "
                index = indices[2] = indices[2] + 1
                indent = f"{base_indent}    "

            # Level 4 header
            if line.startswith("#### "):
                if depth < 4:
                    continue
                prefix = "#### "
                index = indices[3] = indices[3] + 1
                indent = f"{base_indent}        "

            section = line[len(prefix):]
            anchor = section.replace(" ", "-").replace(".", "").replace(",", "").replace("/", "-")
            anchor = anchor.replace("(", "").replace(")", "").lower()

            if split_sections and prefix == "# ":
                if indices[0] > 1:
                    print()
                print(f"## {section}\n")
                continue

            print(f"{indent}{index}. [{section}]({filename}#{anchor})")


if __name__ == "__main__":
    main()
