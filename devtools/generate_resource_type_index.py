#! /usr/bin/env python3

# Requires: python3 (>= 3.11)
# Requires: python3-jinja2

"""
Generate the resource type index for view-files.
"""

from functools import reduce
import os
from pathlib import Path, PosixPath
import re
import sys
from typing import Any
import yaml

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")


# Keep this first so we can use it in the exceptions
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


# pylint: disable-next=too-many-locals
def main() -> None:
    """
    Main function for the program.
    """
    # Before doing anything else, make sure that the user is not running as root
    if os.geteuid() == 0:
        sys.exit("CRITICAL: This program should not be run as the root user; aborting.")

    # This program should be called with the path to the directory to process index-files
    # in, as well as a path to the output file.
    if len(sys.argv) != 3:
        sys.exit("Usage: generate_view_index.py VIEW_DIRECTORY OUTPUT_FILE")

    view_dir = sys.argv[1]
    index_file = sys.argv[2]

    if view_dir.startswith("{HOME}"):
        view_dir = view_dir.replace("{HOME}", Path.home(), 1)
    view_dir = os.path.abspath(view_dir)

    index_file = os.path.abspath(index_file)

    if not os.path.isdir(view_dir):
        sys.exit(f"Error: the specified VIEW_DIRECTORY {view_dir} is not a directory; aborting.")

    yaml_regex: re.Pattern[str] = re.compile(r"^(.*)\.ya?ml$")

    resource_type_index: dict[str, dict[str, str]] = {}

    global_aliases: set[str] = set()

    # We do not need to handle multiple view directories here, so we don't need to build
    # a file index first; we can process the files directly after making sure that they're
    # relevant.
    for filename in natsorted(os.listdir(view_dir)):
        if filename in ("__event_reasons.yaml", index_file):
            continue

        if filename.startswith(("~", ".", "__")):
            continue

        if yaml_regex.match(filename) is None:
            continue

        path = PosixPath(view_dir).joinpath(filename)

        try:
            with open(path, "r", encoding="utf-8") as f:
                tmp = f.read()
                d = yaml.safe_load(tmp)
        except TypeError:
            print(f"The View-file {filename} is invalid; skipping.")
            continue

        kind = deep_get(d, "kind", "")
        api_family = deep_get(d, "api_family", "")

        resource_type = (kind, api_family)

        aliases = set(deep_get(d, "command", []))

        if not global_aliases.isdisjoint(aliases):
            sys.exit(f"Error: overlapping aliases found; {global_aliases.intersection(aliases)} "
                     "exists in several view-files; aborting.")

        for alias in aliases:
            resource_type_index[alias] = {
                "kind": list(resource_type),
                "viewfile": filename,
            }

        global_aliases.update(aliases)

    # Sort the dict; note: this only sorts the dict on a first-level basis,
    # but that's all we really need.
    sorted_dict = dict(sorted(resource_type_index.items(), key=lambda item: item[0]))

    tmp = yaml.dump(sorted_dict, indent=2, sort_keys=True)
    with open(index_file, "w", encoding="utf-8") as f:
        # Start by writing the YAML header
        f.write("%YAML 1.1\n---\n")
        f.write(tmp)


if __name__ == "__main__":
    main()
