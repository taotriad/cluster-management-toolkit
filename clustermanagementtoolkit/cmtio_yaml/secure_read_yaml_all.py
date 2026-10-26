# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Read multiple YAML structs from a file in a secure manner.
"""

from collections.abc import Generator, Iterator
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


def secure_read_yaml_all(path: FilePath, **kwargs: Any) -> Generator | Iterator:
    """
    Read all dicts in YAML-format from a file in a safe manner
    Note: since the return type from safe_load_all() is an iterator
    evaluation does not happen until iterating; this means that exceptions
    must be handled when iterating rather than when getting the return value.

        Parameters:
            path (FilePath): The path to read from
            **kwargs (dict[str, Any]): Keyword arguments
                checks ([SecurityChecks]): A list of checks that should be performed
                directory_is_symlink (bool): The dir that the path points to is a symlink
                temporary (bool): Is the file a tempfile?
                                  If so we need to disable the check for parent permissions
                asynchronous (bool): The data should be read asynchronously; use PyYAML
        Returns:
            Generator | Iterator: An generator or iterator of data
        Raises:
            FileNotFoundError
            cmttypes.FilePathAuditError
            ruyaml.composer.ComposerError
            ruyaml.scanner.ScannerError
            ruyaml.parser.ParserError
            ruamel.yaml.constructor.DuplicateKeyError
    """
    checks: list[SecurityChecks] | None = deep_get(kwargs, DictPath("checks"), None)
    directory_is_symlink: bool = deep_get(kwargs, DictPath("directory_is_symlink"), False)
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)
    asynchronous: bool = deep_get(kwargs, DictPath("asynchronous"), False)

    string = secure_read_string(path, checks=checks,
                                directory_is_symlink=directory_is_symlink,
                                temporary=temporary)
    if asynchronous:
        return yaml.safe_load_all(string)
    return ryaml.load_all(string)
