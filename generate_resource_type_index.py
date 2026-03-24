#! /bin/sh
# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
''''eval version=$( ls /usr/bin/python3.* | \
    grep '.*[0-9]$' | sort -nr -k2 -t. | head -n1 ) && \
    version=${version##/usr/bin/python3.} && [ ${version} ] && \
    [ ${version} -ge 11 ] && exec /usr/bin/python3.${version} "$0" "$@" || \
    exec /usr/bin/env python3 "$0" "$@"' #'''
# The above hack is to handle distros where /usr/bin/python3
# doesn't point to the latest version of python3 they provide

# Requires: python3 (>= 3.11)
# Requires: python3-jinja2
import os
from pathlib import Path, PosixPath
import re
import sys

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmttypes import deep_get, DictPath, FilePath, SecurityStatus, LogLevel

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml
from clustermanagementtoolkit import cmtpaths
from clustermanagementtoolkit.cmtpaths import CMT_CONFIG_FILE, CMT_CONFIG_FILENAME, HOMEDIR
from clustermanagementtoolkit.cmtpaths import DEFAULT_THEME_FILE, VIEW_DIR, SYSTEM_VIEWS_DIR

from clustermanagementtoolkit.cmtlib import read_cmtconfig

def main() -> None:
    """
    Main function for the program.
    """
    # Before doing anything else, make sure that the user is not running as root
    if os.geteuid() == 0:
        sys.exit("CRITICAL: This program should not be run as the root user; aborting.")

    # Then initialise the configuration file
    read_cmtconfig()

    # This program should be called with the path to the directory to process index-files
    # in, as well as a path to the output file.
    if len(sys.argv) != 3:
        sys.exit("Usage: generate_view_index.py VIEW_DIRECTORY OUTPUT_FILE")

    view_dir = sys.argv[1]
    index_file = sys.argv[2]

    if view_dir.startswith("{HOME}"):
        view_dir = view_dir.replace("{HOME}", HOMEDIR, 1)
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

        path = FilePath(view_dir).joinpath(filename)

        try:
            d = dict(secure_read_yaml(path, directory_is_symlink=True, asynchronous=True))
        except (TypeError) as e:
            print(f"The View-file {filename} is invalid; skipping.")
            continue

        kind = deep_get(d, DictPath("kind"), "")
        api_family = deep_get(d, DictPath("api_family"), "")

        resource_type = (kind, api_family)

        aliases = set(deep_get(d, DictPath("command"), []))

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
    sorted_dict = {key: value for key, value in sorted(resource_type_index.items(),
                                                       key=lambda item: item[0])}
    secure_write_yaml(index_file, sorted_dict, sort_keys=True, yaml_version=(1, 1))


if __name__ == "__main__":
    main()
