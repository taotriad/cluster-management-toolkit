# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Get the latest version for component in a GitHub repository.
"""

import re
import sys
import tempfile

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.networkio.download_files import download_files


def get_github_version(url: str, version_regex: str) -> tuple[list[str], str, str] | None:
    """
    Given a github repository find the latest release;
    exclude releases that do not match the regex and prereleases.

        Parameters:
            url (str): The github API URL to check for latest version
            version_regex (str): A regex
        Returns:
            ([str], str):
                ([str]): A list of version number elements, or None in case of failure
                (str): The release data
                (str): The release page body
    """
    versions: list[tuple[list[str], str, str]] = []

    if url is not None and url and version_regex is not None and version_regex:
        compiled_version_regex = re.compile(version_regex)
        with tempfile.TemporaryDirectory() as td:
            if not download_files(td, [(url, "releases.yaml", None, None)], permissions=0o600):
                return None
            try:
                tmp = list(secure_read_yaml(FilePath(f"{td}/releases.yaml")))
            except TypeError:
                tmp = []
            for release in tmp:
                prerelease = deep_get(release, DictPath("prerelease"), False)
                draft = deep_get(release, DictPath("draft"), False)
                if prerelease or draft:
                    continue
                name = deep_get(release, DictPath("tag_name"), "")
                if (re_tmp := compiled_version_regex.match(name)) is None:
                    continue
                created_at = deep_get(release, DictPath("created_at"), "<unknown>")
                published_at = deep_get(release, DictPath("published_at"), created_at)
                body = deep_get(release, DictPath("body"), "")
                versions.append((list(re_tmp.groups()), published_at, body))
    if versions:
        return natsorted(versions, reverse=True)[0]

    return [], "", ""
