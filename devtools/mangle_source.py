#! /usr/bin/env python3

# Copyright David Weinehall.
# SPDX-License-Identifier: MIT

"""
This program replaces the shebang of a Python 3 with a shebang that works
on systems where the default Python isn't the most recent version installed
on the system.
"""

import errno
import sys


hack = [
    "#! /bin/sh",

    "# vim: ts=4 filetype=python expandtab "
    "shiftwidth=4 softtabstop=4 syntax=python",

    "''''eval version=$( ls /usr/bin/python3.* | \\",

    "    grep '.*[0-9]$' | sort -nr -k2 -t. | head -n1 ) && \\",

    "    version=${version##/usr/bin/python3.} && [ ${version} ] && \\",

    "    [ ${version} -ge 9 ] && exec /usr/bin/python3.${version} "
    "\"$0\" \"$@\" || \\",

    "    exec /usr/bin/env python3 \"$0\" \"$@\"' #'''",

    "# The above hack is to handle distros where /usr/bin/python3",

    "# doesn't point to the latest version of python3 they provide",
]


def main() -> int:
    """
    Main function for the program.

        Returns:
            0 on success, errno on failure
    """
    lines = []
    filename: str = ""

    if len(sys.argv) == 2:
        filename = sys.argv[1]
        try:
            with open(filename, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        except FileNotFoundError:
            print("File not found.")
            sys.exit(errno.ENOENT)
    else:
        print("mangle_source.py takes exactly 1 argument; PATH")
        sys.exit(errno.EINVAL)

    valid_shebangs = (
        "#! /usr/bin/env python3",
        "#!/usr/bin/env python3",
        "#! /usr/bin/python3",
        "#!/usr/bin/python3",
    )
    if len(lines) > 2 and lines[0] in valid_shebangs \
            and lines[1] == "# [:::MUNGE SHEBANG:::]":
        # Remove the shebang and the munge marker
        lines.pop(0)
        lines.pop(0)
        lines = hack + lines
    else:
        print(f"File {filename} does not start with a supported Python 3 shebang line;",
              file=sys.stderr)
        print("supported shebangs are:", file=sys.stderr)
        for shebang in valid_shebangs:
            print(f"  {shebang}", file=sys.stderr)
        print("Ignoring.\n", file=sys.stderr)

    for line in lines:
        print(line)

    return 0


if __name__ == "__main__":
    main()
