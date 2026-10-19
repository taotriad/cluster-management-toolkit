# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Update the version cache for externally monitored resources.
"""

from collections.abc import Callable
from datetime import datetime, UTC
from pathlib import Path
import re
import sys
from typing import Any, cast

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtio import secure_write_string

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml, secure_write_yaml

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit import cmtpaths
from clustermanagementtoolkit.cmtpaths import HOMEDIR
from clustermanagementtoolkit.cmtpaths import VERSION_CACHE_DIR
from clustermanagementtoolkit.cmtpaths import VERSION_CACHE_LAST_UPDATED_PATH
from clustermanagementtoolkit.cmtpaths import VERSION_CANDIDATES_FILE

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.networkio.candidate_version_function_allowlist import candidate_version_function_allowlist  # noqa: E501
from clustermanagementtoolkit.networkio.download_files import download_files
from clustermanagementtoolkit.networkio.reformatter_allowlist import reformatter_allowlist


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def update_version_cache(**kwargs: Any) -> None:
    """
    Update the list of component versions, and, where applicable, fetch their changelogs

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                software_sources_dir (FilePath): Path to the software-sources dir (optional)
                                                 Default: "{HOME}/.cmt/sources"
                verbose (bool): True for verbose output about actions
                force (bool): Force update the cache even if the interval isn't exceeded
    """
    software_sources_dir = \
        deep_get(kwargs, DictPath("software_sources_dir"), cmtpaths.SOFTWARE_SOURCES_DIR)
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)
    force: bool = deep_get(kwargs, DictPath("force"), False)
    # Substitute {HOME}/ for {HOMEDIR}
    if software_sources_dir.startswith(("{HOME}/", "{HOME}\\")):
        software_sources_dir = HOMEDIR.joinpath(software_sources_dir[len('{HOME}/'):])

    sources: dict = {}
    try:
        for path in natsorted(Path(cmtpaths.SYSTEM_SOFTWARE_SOURCES_DIR).iterdir()):
            if not path.name.endswith((".yml", ".yaml")):
                continue
            source = dict(secure_read_yaml(FilePath(path), directory_is_symlink=True))
            for key, data in source.items():
                if verbose and key in sources:
                    old_path = deep_get(sources, DictPath(f"{key}#entry_path"), {})
                    ansithemeprint([ANSIThemeStr("Note", "note"),
                                    ANSIThemeStr(": overriding entry ", "default"),
                                    ANSIThemeStr(f"{key}", "emphasis"),
                                    ANSIThemeStr(" from ", "default"),
                                    ANSIThemeStr(f"{old_path}", "path"),
                                    ANSIThemeStr(" with entry from ", "default"),
                                    ANSIThemeStr(f"{path.name}", "path")])
                    sources.pop(key)
                sources[key] = data
    except (FileNotFoundError, TypeError):
        pass

    try:
        for path in natsorted(Path(software_sources_dir).iterdir()):
            if not path.name.endswith((".yml", ".yaml")):
                continue
            source = dict(secure_read_yaml(FilePath(path), directory_is_symlink=True))
            for key, data in source.items():
                if verbose and key in sources:
                    old_path = deep_get(sources, DictPath(f"{key}#entry_path"), {})
                    ansithemeprint([ANSIThemeStr("Note", "note"),
                                    ANSIThemeStr(": overriding entry ", "default"),
                                    ANSIThemeStr(f"{key}", "emphasis"),
                                    ANSIThemeStr(" from ", "default"),
                                    ANSIThemeStr(f"{old_path}", "path"),
                                    ANSIThemeStr(" with entry from ", "default"),
                                    ANSIThemeStr(f"{path.name}", "path")])
                    sources.pop(key)
                sources[key] = data
    except (FileNotFoundError, TypeError):
        pass

    if Path(VERSION_CACHE_LAST_UPDATED_PATH).is_file():
        try:
            last_update_data = dict(secure_read_yaml(VERSION_CACHE_LAST_UPDATED_PATH))
        except TypeError:
            last_update_data = {}
    else:
        last_update_data = {}
    if last_update_data is None:
        last_update_data = {}

    try:
        candidate_versions = dict(secure_read_yaml(VERSION_CANDIDATES_FILE))
    except TypeError:
        candidate_versions = {}
    except FilePathAuditError as e:
        if "DOES_NOT_EXIST" in str(e):
            candidate_versions = {}
        else:
            raise

    changed = False

    for key, data in sources.items():
        description: str = deep_get(data, DictPath("description"), "<no description available>")
        if verbose:
            ansithemeprint([ANSIThemeStr("  • ", "separator"),
                            ANSIThemeStr(description, "programname")])
        interval = deep_get(data, DictPath("interval"), 60 * 60)
        version_last_updated = deep_get(last_update_data, DictPath(f"{key}#version"))
        version_age = None
        if version_last_updated:
            try:
                version_age = datetime.now(UTC) - version_last_updated
            except TypeError:
                # version_last_updated used to use offset-naïve timestamps;
                # if we encounter one of those we ignore the timestamp,
                # which will trigger an update.
                pass
        changelog_last_updated = deep_get(last_update_data, DictPath(f"{key}#changelog"))
        changelog_age = None
        if changelog_last_updated:
            try:
                changelog_age = datetime.now(UTC) - changelog_last_updated
            except TypeError:
                # changelog_last_updated used to use offset-naïve timestamps;
                # if we encounter one of those we ignore the timestamp,
                # which will trigger an update.
                pass
        tmp: str = deep_get(data, DictPath("candidate_version#function"), "")
        candidate_version_func: Callable | None = \
            deep_get(candidate_version_function_allowlist, DictPath(tmp))
        candidate_version_args: dict = deep_get(data, DictPath("candidate_version#args"), {})

        candidate_version_tuple: tuple | None = None
        release_body = ""

        # By default we only update the cache once per hour unless forced
        # or the configuration says differently
        if force or not version_age or version_age.days > 0 or version_age.seconds > interval:
            if candidate_version_func:
                if verbose:
                    ansithemeprint([ANSIThemeStr("    Downloading version data.", "default")])
                release_info = candidate_version_func(**candidate_version_args)
                if release_info is not None:
                    candidate_version_tuple, release_date, release_body = release_info
                    if key not in candidate_versions:
                        candidate_versions[key] = {"release": "", "release_date": ""}
                    candidate_versions[key]["release"] = \
                        "".join(cast(tuple, candidate_version_tuple))
                    candidate_versions[key]["release_date"] = "".join(release_date)
                    if key not in last_update_data:
                        last_update_data[key] = {}
                    last_update_data[key]["version"] = datetime.now(UTC)
                    secure_write_yaml(VERSION_CACHE_LAST_UPDATED_PATH,
                                      last_update_data, permissions=0o644)
            changed = True
        else:
            if verbose:
                ansithemeprint([ANSIThemeStr("    Note", "note"),
                                ANSIThemeStr(": Version data is recent; not updating.", "default")])

        if candidate_version_tuple is None:
            # If we've already fetched the data recently we need to use the existing data.
            tmp = deep_get(candidate_versions, DictPath(f"{key}#release"), "")
            if not tmp:
                continue
            # Split it using the same regex that we'd normally use to split the string.
            candidate_version_regex = \
                deep_get(candidate_version_args, DictPath("version_regex"), "")
            if (re_tmp := re.match(candidate_version_regex, tmp)) is not None:
                candidate_version_tuple = re_tmp.groups()

        if not (force or not changelog_age
                or changelog_age.days > 0 or changelog_age.seconds > interval):
            if verbose:
                ansithemeprint([ANSIThemeStr("    Note", "note"),
                                ANSIThemeStr(": Changelog is recent; not downloading.", "default")])
            continue

        # We (hopefully) have a version now; time to fetch the changelog (if requested)
        changelog_url: str = deep_get(data, DictPath("changelog#url"), "")
        changelog_dest: str = deep_get(data, DictPath("changelog#dest"), "")
        changelog_from_body: str = deep_get(data, DictPath("changelog#from_body"), False)
        reformatter: str = deep_get(data, DictPath("changelog#reformatter"))

        if not (changelog_url or changelog_from_body and release_body) or not changelog_dest:
            continue

        if changelog_from_body:
            # First step: replace \r\n with \n.
            release_body = release_body.replace("\r\n", "\n")
            # Add extra newlines at the end; one to help the reformatter,
            # one because the field typically lacks a trailing newline.
            release_body += "\n\n\n"

            if (reformatter := deep_get(reformatter_allowlist, DictPath(reformatter))) is not None:
                release_body = reformatter(release_body)
            secure_write_string(VERSION_CACHE_DIR.joinpath(changelog_dest), release_body,
                                allow_relative_path=True, permissions=0o644)
        else:
            version_substitutions: dict = {}
            if candidate_version_tuple:
                for i, item in enumerate(candidate_version_tuple):
                    version_substitutions[f"<<<version.{i}>>>"] = item
            changelog_url = cmtlib.substitute_string(changelog_url, version_substitutions)
            if "<<<version" in changelog_url:
                # If still have remaining substitutions to be made after using the versions we have
                # there is no recourse but to skip fetching the changelog.
                continue
            fetch_url = [(changelog_url, changelog_dest, None, None)]
            if verbose:
                ansithemeprint([ANSIThemeStr("    Downloading changelog.", "default")])
            if not download_files(VERSION_CACHE_DIR, fetch_url):
                ansithemeprint([ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(": Failed to fetch ", "default"),
                                ANSIThemeStr(f"{changelog_url}", "uri"),
                                ANSIThemeStr("; skipping.", "default")], stderr=True)
                continue
        if key not in last_update_data:
            last_update_data[key] = {}
        last_update_data[key]["changelog"] = datetime.now(UTC)
        secure_write_yaml(VERSION_CACHE_LAST_UPDATED_PATH,
                          last_update_data, permissions=0o644)

    if changed:
        secure_write_yaml(VERSION_CANDIDATES_FILE, candidate_versions, permissions=0o644)
