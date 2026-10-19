# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Read a single YAML struct from a file in a secure manner.
"""

import sys
from typing import Any
try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import yaml; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install PyYAML`; aborting.")

try:
    import ruyaml  # type: ignore[import-not-found,unused-ignore]
    ryaml = ruyaml.YAML()
    sryaml = ruyaml.YAML(typ="safe")
except ModuleNotFoundError:  # pragma: no cover
    try:
        import ruamel.yaml as ruyaml  # type: ignore[no-redef,unused-ignore]
        ryaml = ruyaml.YAML()
        sryaml = ruyaml.YAML(typ="safe")
    except ModuleNotFoundError:  # pragma: no cover
        sys.exit("ModuleNotFoundError: Could not import ruyaml/ruamel.yaml; "
                 "you may need to (re-)run `cmt-install.py` or `pip3 install ruyaml/ruamel.yaml`; "
                 "aborting.")

from clustermanagementtoolkit.cmtio import secure_read_string

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import deep_get


def secure_read_yaml(path: FilePath, **kwargs: Any) -> dict | \
                                                       ruyaml.comments.CommentedMap | \
                                                       ruyaml.comments.CommentedSeq:
    """
    Read data in YAML-format from a file in a safe manner.

        Parameters:
            path (FilePath): The path to read from
            **kwargs (dict[str, Any]): Keyword arguments
                checks ([SecurityChecks]): A list of checks that should be performed
                directory_is_symlink (bool): The dir that the path points to is a symlink
                temporary (bool): Is the file a tempfile?
                                  If so we need to disable the check for parent permissions
                asynchronous (bool): The data should be read asynchronously; use PyYAML
        Returns:
            yaml_data
                (dict|ruyaml.comments.CommentedMap|ruyaml.comments.CommentedSeq): The read YAML-data
        Raises:
            ruyaml.composer.ComposerError (synchronous mode)
            ruyaml.parser.ParserError (synchronous mode)
            ruyaml.scanner.ScannerError (synchronous mode)
            ruyaml.constructor.DuplicateKeyError (synchronous mode)
            yaml.parser.ParserError (asynchronous mode)
            FileNotFoundError
            cmttypes.FilePathAuditError
    """
    checks: list[SecurityChecks] | None = deep_get(kwargs, DictPath("checks"), None)
    directory_is_symlink: bool = deep_get(kwargs, DictPath("directory_is_symlink"), False)
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)
    asynchronous: bool = deep_get(kwargs, DictPath("asynchronous"), False)

    string = secure_read_string(path, checks=checks,
                                directory_is_symlink=directory_is_symlink,
                                temporary=temporary)
    if asynchronous:
        return yaml.safe_load(string)

    # First parse the data with safe parser; this will throw an exception if there are issues.
    try:
        _d2 = sryaml.load(string)
    except ruyaml.constructor.DuplicateKeyError as e:
        raise ruyaml.constructor.DuplicateKeyError(f"Duplicate keys in file: {path}") from e
    except ruyaml.parser.ParserError as e:
        raise ruyaml.parser.ParserError(f"Failed to parse file: {path}") from e

    # If nothing went wrong, we import the round-trip formatted data.
    tmp = ryaml.load(string)
    return tmp
