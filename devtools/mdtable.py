#! /usr/bin/env python3

# Requires: python3 (>= 3.11)

# Copyright David Weinehall
# SPDX-License-Identifier: MIT

"""
Reformat tabulated data to Markdown.
"""

import errno
import re
import sys
from typing import Any, NoReturn

PROGRAMNAME = "mdtable.py"
PROGRAMVERSION = "v0.0.8"

PROGRAMDESCRIPTION: str = "Reformat tabulated data to Markdown"
PROGRAMAUTHORS: str = "Written by David Weinehall."

COPYRIGHT: str = "Copyright © 2024-2026 David Weinehall"

LICENSE: str = "This is free software; see the source for copying conditions.  There is NO\n" \
               "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."


def usage() -> NoReturn:
    """
    Display usage information.
    """
    print(f"{PROGRAMNAME} [OPTIONS] FILE [=]HEADER[=]...")
    print()
    print(PROGRAMDESCRIPTION)
    print()
    print("Given a file with columnised data, split it using SEPARATOR")
    print("and format it as a Markdown table using HEADER...")
    print()
    print("The program can also reformat existing Markdown tables.")
    print()
    print("=HEADER  will left-align the column (default behaviour)")
    print(" HEADER= will right-align the column")
    print("=HEADER= will center-align the column")
    print()
    print("Options:")
    print("  --reformat               Take a pre-formatted Markdown table as indata")
    print("  --separator SEPARATOR    The separator used in FILE; default \"|\"")
    print("  --bold-footer            Make all entries in the last row of the table bold")
    print("  --bold-regex REGEX       A regular expression to apply bold formatting to")
    print("  --italics-regex REGEX    A regular expression to apply italics formatting to")
    print()
    print("help|--help         Display this help and exit")
    print("version|--version   Output version information and exit")
    print()
    print("Since Markdown tables have no concept of footers we implement this by making every")
    print("entry on the matching line(s) bold instead.")

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


# pylint: disable-next=too-many-branches,too-many-locals,too-many-statements
def format_table(file: str, separator: str, headers: list[str], **kwargs: Any) -> None:
    """
    Format field-separated data as a Markdown table.

        Parameters:
            file (str): The name of the file to read data from
            separator (str): The separator that separates the fields
            headers ([str]): The field headers
            **kwargs (dict[str, Any]): Keyword arguments
                bold_footer (bool): Make all entries in the last row bold
                bold_regex (str): A regular expression to check for matches to apply bold to
                italics_regex (str): A regular expression to check for matches to apply italics to
                reformat (bool): Take an existing Markdown table as input and reforamt it
    """
    lines: str = ""
    bold_footer: bool = kwargs.get("bold_footer", False)
    bold_regex: str = kwargs.get("bold_regex", "")
    italics_regex: str = kwargs.get("italics_regex", "")
    reformat: bool = kwargs.get("reformat", False)

    try:
        with open(file, "r", encoding="utf-8") as f:
            lines = f.read()
    except FileNotFoundError:
        print(f"{PROGRAMNAME}: \"{file}\": File not found.")
        sys.exit(errno.ENOENT)

    # Remove trailing empty lines
    lines = lines.rstrip("\n")
    splitlines = lines.split("\n")

    if not splitlines:
        print(f"{PROGRAMNAME}: \"{file}\": is empty.")
        sys.exit(errno.EINVAL)

    if reformat:
        new_splitlines = []

        # Remove surrounding whitespace and table edges
        for line in splitlines:
            new_splitlines.append(line.strip().strip("|"))

        splitlines = new_splitlines

        if not splitlines[0]:
            print(f"{PROGRAMNAME}: Inconsistent input data.")
            print("The first line is empty.")
            sys.exit(errno.EINVAL)

        if headers:
            tmpheaders = headers
        else:
            tmpheaders = splitlines[0].split("|")
        headers = [header.strip() for header in tmpheaders]

        if len(splitlines) > 1 and not splitlines[1]:
            print(f"{PROGRAMNAME}: Inconsistent input data.")
            print("The second line is empty.")
            sys.exit(errno.EINVAL)

        tmpalignments = splitlines[1].split("|")

        if len(tmpalignments) != len(headers):
            print(f"{PROGRAMNAME}: Inconsistent input data.")
            print(f"{len(headers)} headers were provided, "
                  f"but the table has {len(tmpalignments)} header dividers.")
            sys.exit(errno.EINVAL)

        for i, alignment in enumerate(tmpalignments):
            alignment = alignment.strip()

            # User-supplied alignment overrides that from the document.
            if headers[i].startswith("=") or headers[i].endswith("="):
                continue

            if alignment.startswith(":") and not alignment.endswith(":"):
                headers[i] = f"={headers[i].strip('=')}"
            elif alignment.endswith(":") and not alignment.startswith(":"):
                headers[i] = f"{headers[i].strip('=')}="
            elif alignment.endswith(":") and alignment.startswith(":"):
                headers[i] = f"={headers[i].strip('=')}="
        splitlines = splitlines[2:]

    column_count: int = len(headers)
    widths: list[int] = [len(header.strip().strip("=")) for header in headers]
    adjusts: list[int] = [0 for header in headers]

    tablelen = len(splitlines)

    # First check for consistency and tabulate column widths
    for i, line in enumerate(splitlines):
        columns: list[str] = line.split(separator)
        if column_count != len(columns):
            if i == 0:
                print(f"{PROGRAMNAME}: Inconsistent input data.")
                print(f"{column_count} headers were provided, "
                      f"while line {i} has {len(columns)} columns.")
            else:
                print(f"{PROGRAMNAME}: Inconsistent input data.")
                print(f"The first line has {column_count} columns, "
                      f"while line {i} has {len(columns)} columns.")
            sys.exit(errno.EINVAL)

        for j, column in enumerate(columns):
            adjust = 0
            if bold_regex or (bold_footer and tablelen - 1 == i):
                if re.match(bold_regex, column) is not None:
                    adjust = 2
            if italics_regex and not adjust:
                if re.match(italics_regex, column) is not None:
                    adjust = 1
            adjusts[j] = max(adjusts[j], adjust)
            widths[j] = max(widths[j], len(column.strip()) + adjust)

    table: str = "|"

    alignments = []

    for i, header in enumerate(headers):
        if widths[i] == 2:
            continue
        if header.startswith("="):
            if header.endswith("="):
                # Center align
                alignments.append("^")
            else:
                # Left align
                alignments.append("<")
        elif header.endswith("="):
            # Right align
            alignments.append(">")
        else:
            # Default: left align
            alignments.append("<")

        alignwidth = widths[i] + adjusts[i]
        formatstr = f":{alignments[i]}{alignwidth}"
        formatstr2 = " {" + formatstr + "} |"
        table += formatstr2.format(header.strip("="))

    table += "\n|"

    for i, header in enumerate(headers):
        if widths[i] == 2:
            continue
        table += " "
        if alignments[i] == "^":
            # Center align
            table += ":".ljust(widths[i] + adjusts[i] - 1, "-")
            table += ":"
        elif alignments[i] == ">":
            # Right align
            table += "".ljust(widths[i] + adjusts[i] - 1, "-")
            table += ":"
        else:
            # Left align
            table += ":".ljust(widths[i] + adjusts[i], "-")
        table += " |"

    # Now format the data
    for i, line in enumerate(splitlines):
        columns = line.split(separator)
        table += "\n|"
        for j, column in enumerate(columns):
            if widths[j] == 2:
                continue

            before = ""
            after = ""
            if bold_regex or (bold_footer and tablelen - 1 == i):
                if re.match(bold_regex, column) is not None:
                    before = "**"
                    after = "**"
            if italics_regex and before == "" and not (bold_footer and tablelen - 1 == i):
                print(f"{bold_footer=}\n{tablelen - 1=}\n{i=}")
                if re.match(italics_regex, column) is not None:
                    before = "*"
                    after = "*"

            column = column.strip()

            # Just to make sure we don't add extra italics/bold.
            if before == "**" and after == "**" \
                    and column.startswith("**") and column.endswith("**"):
                column = column.strip("**")
            elif before == "*" and after == "*" \
                    and column.startswith("*") and column.endswith("*"):
                column = column.strip("*")

            column = f"{before}{column}{after}"
            alignwidth = widths[j] + adjusts[j]
            formatstr = f":{alignments[j]}{alignwidth}"
            formatstr2 = " {" + formatstr + "} |"
            table += formatstr2.format(column)

    print(table)


# pylint: disable-next=too-many-branches,too-many-statements
def main() -> None:
    """
    Main function for the program.
    """

    if len(sys.argv) == 1:
        print(f"{PROGRAMNAME}: Missing operand.")
        print(f"Try \"{PROGRAMNAME} --help\" for more information.")
        sys.exit(errno.EINVAL)

    separator: str = "|"
    bold_footer: bool = False
    bold_regex: str = ""
    italics_regex: str = ""
    reformat: bool = False

    i = 1

    while i < len(sys.argv):
        opt = sys.argv[i]
        i += 1
        if opt in ("help", "--help"):
            usage()
        elif opt in ("version", "--version"):
            version()
        elif not opt.startswith("--"):
            i -= 1
            break
        elif opt == "--reformat":
            reformat = True
        elif opt == "--bold-footer":
            bold_footer = True
        elif opt == "--bold-regex":
            if len(sys.argv) < i + 1:
                print(f"{PROGRAMNAME}: \"--bold-regex\" missing argument.")
                print(f"Try \"{PROGRAMNAME} --help\" for more information.")
                sys.exit(errno.EINVAL)
            bold_regex = sys.argv[i]
            i += 1
        elif opt == "--italics-regex":
            if len(sys.argv) < i + 1:
                print(f"{PROGRAMNAME}: \"--italics-regex\" missing argument.")
                print(f"Try \"{PROGRAMNAME} --help\" for more information.")
                sys.exit(errno.EINVAL)
            italics_regex = sys.argv[i]
            i += 1
        elif opt == "--separator":
            if len(sys.argv) < i + 1:
                print(f"{PROGRAMNAME}: \"--separator\" missing argument.")
                print(f"Try \"{PROGRAMNAME} --help\" for more information.")
                sys.exit(errno.EINVAL)
            separator = sys.argv[i]
            i += 1

    if len(sys.argv) - i < 1:
        print(f"{PROGRAMNAME}: Missing FILE.")
        print(f"Try \"{PROGRAMNAME} --help\" for more information.")
        sys.exit(errno.EINVAL)

    file = sys.argv[i]

    if len(sys.argv) - 2 < 1:
        print(f"{PROGRAMNAME}: Missing HEADER...")
        print(f"Try \"{PROGRAMNAME} --help\" for more information.")
        sys.exit(errno.EINVAL)

    headers = sys.argv[i + 1:]

    format_table(file, separator, headers, bold_footer=bold_footer,
                 bold_regex=bold_regex, italics_regex=italics_regex, reformat=reformat)


if __name__ == "__main__":
    main()
