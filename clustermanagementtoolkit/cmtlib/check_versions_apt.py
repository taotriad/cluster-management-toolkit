# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
import sys

from clustermanagementtoolkit.cmtio import execute_command_with_response
from clustermanagementtoolkit.cmtio import secure_which

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityPolicy


def __extract_version(line: str) -> str:
    """
    Extract a version from an apt-cache madison entry.

        Parameters:
            line (str): A package info line from apt-cache madison
        Returns:
            (str): A version number
    """
    if not isinstance(line, str):
        raise TypeError(f"{line} is type: {type}; expected str")

    tmp = line.split("|")
    if len(tmp) != 3:
        raise ValueError("Failed to extract a version; "
                         "this is (most likely) a programming error.")
    return tmp[1].strip()


# pylint: disable-next=too-many-locals,too-many-branches
def check_versions_apt(packages: list[str]) -> list[tuple[str, str, str, list[str]]]:
    """
    Given a list of packages, return installed, candidate, and all available versions.

        Parameters:
            packages ([str]): A list of packages to get versions for
        Returns:
            ([(str, str, str, [str])]): A list of package versions
    """
    try:
        # This is for the benefit of avoiding dependency cycles
        # pylint: disable-next=import-outside-toplevel
        from natsort import natsorted
    except ModuleNotFoundError:  # pragma: no cover
        sys.exit("ModuleNotFoundError: Could not import natsort; "
                 "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

    versions = []

    if not isinstance(packages, (list, tuple)):
        raise TypeError(f"packages must be a list or tuple, got {type(packages)}")

    apt_cache_path = secure_which(FilePath("apt-cache"),
                                  fallback_allowlist=["/bin", "/usr/bin"],
                                  security_policy=SecurityPolicy.ALLOWLIST_STRICT)
    args = [apt_cache_path, "policy"] + packages
    response, _retval = execute_command_with_response(args)
    split_response = response.splitlines()
    installed_regex = re.compile(r"^\s*Installed: (.*)")
    candidate_regex = re.compile(r"^\s*Candidate: (.*)")
    for line in split_response:
        if line.endswith(":"):
            package = line[:-1]
        elif line.startswith("  Installed: "):
            tmp = installed_regex.match(line)
            if tmp is not None:
                if tmp[1] == "(none)":
                    installed_version = "<none>"
                else:
                    installed_version = tmp[1]
            else:
                installed_version = "<none>"
        elif line.startswith("  Candidate: "):
            tmp = candidate_regex.match(line)
            if tmp is not None and tmp[1] != installed_version:
                if tmp[1] == "(none)":
                    if installed_version == "<none>":
                        continue
                    candidate_version = "<none>"
                else:
                    candidate_version = tmp[1]
            else:
                candidate_version = ""
            # We have the current and candidate version now;
            # get all the other versions of the same package
            apt_cache_path = secure_which(FilePath("apt-cache"),
                                          fallback_allowlist=["/bin", "/usr/bin"],
                                          security_policy=SecurityPolicy.ALLOWLIST_STRICT)
            args2 = [apt_cache_path, "madison", package]
            response2, _retval = execute_command_with_response(args2)
            split_response2 = response2.splitlines()
            all_versions = []
            for version in split_response2:
                if version.endswith(" Packages"):
                    all_versions.append(__extract_version(version))
            natsorted_versions = []
            for natsorted_version in natsorted(all_versions, reverse=True):
                natsorted_versions.append(str(natsorted_version))
            versions.append((package, installed_version, candidate_version, natsorted_versions))

    return versions
