# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import os
from pathlib import Path, PurePath

from clustermanagementtoolkit.cmtio.check_path import check_path

from clustermanagementtoolkit.cmtpaths import HOMEDIR

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityPolicy
from clustermanagementtoolkit.cmttypes import SecurityStatus


# pylint: disable-next=too-many-branches
def secure_which(path: FilePath, fallback_allowlist: list[str],
                 security_policy: SecurityPolicy = SecurityPolicy.STRICT,
                 executable: bool = True) -> FilePath:
    """
    Path is the default path where the file expected to be found,
    or if no such default path exists, just the base name of the file.

    Path resolution occurs as follows:

    1. If the file exists at the location, and meets the security criteria
       imposed by security_policy, it will be returned.

    2. If not, and the security policy permits, the entries in fallback_allowlist
       will be used as parent for the filename to check for matches.

    3. If no matches are found in step 2, and security_policy permits,
       path will be passed to shutil.which().

        Parameters:
            paths ([FilePath]): A list of paths to the executable
            security_policy (SecurityPolicy): The policy to use when deciding whether or not
                                              it is OK to use the file at the path.
            executable (bool): Should the path point to an executable?
        Returns:
            (FilePath): A path to the executable
        Exceptions:
            FileNotFoundError: Raised whenever no executable could be found
                               that matched both path and security criteria
            RuntimeError: The path loops
    """
    fully_resolved_paths = []

    for allowed_path in fallback_allowlist:
        if Path(allowed_path).resolve() == Path(allowed_path):
            fully_resolved_paths.append(allowed_path)

    checks: list[SecurityChecks] = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_FILE,
    ]

    if executable:
        checks.append(SecurityChecks.IS_EXECUTABLE)
    else:
        checks.append(SecurityChecks.PERMISSIONS)

    violations = check_path(path, checks=checks)

    if violations == [SecurityStatus.OK]:
        return path

    # If we are using SecurityPolicy.STRICT we fail if we cannot find a match here
    if security_policy == SecurityPolicy.STRICT:
        raise FileNotFoundError(f"secure_which() could not find an acceptable match for {path}")

    # If the security policy is ALLOWLIST* and fallback_allowlist is not empty,
    # all paths in the fallback list will be tested one at a time with the basename from path,
    # until a match is found (or the list reaches the end).
    #
    # ALLOWLIST_STRICT behaves like STRICT, except with an allowlist
    # ALLOWLIST_RELAXED additionally allows the path not to resolve to itself,
    # as long as it resolves to a path in the allowlist that resolves to itself.

    # Try the fallback options one by one
    name = PurePath(path).name

    tmp_allowlist = []
    for directory in fallback_allowlist:
        if directory.startswith("{HOME}"):
            directory = directory.replace("{HOME}", HOMEDIR, 1)

        tmp_allowlist.append(directory)

    fallback_allowlist = tmp_allowlist

    for directory in fallback_allowlist:
        path = FilePath(os.path.join(directory, name))

        violations = check_path(path, checks=checks)

        if violations != [SecurityStatus.OK]:
            if security_policy == SecurityPolicy.ALLOWLIST_STRICT:
                continue

            if SecurityStatus.DOES_NOT_EXIST in violations:
                continue

            # If the only violation is that the path does not resolve to
            # itself, but it resolves to a path that otherwise has no violations
            # and that is within the fallback_allowlist (and that entry in turn
            # resolves to itself) we return the path if policy is relaxed.
            # Since the behaviour of the called program might change if we call it
            # by a different name we do not return the resolved path; we return
            # the original path
            if len({SecurityStatus.PATH_NOT_RESOLVING_TO_SELF,
                    SecurityStatus.PARENT_PATH_NOT_RESOLVING_TO_SELF}.union(violations)) <= 2:
                return path
            continue

        return path

    raise FileNotFoundError(f"secure_which() could not find an acceptable match for {name}")
