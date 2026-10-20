# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Write YAML data to a file in a secure manner.
"""

import sys
from typing import Any

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

from clustermanagementtoolkit.cmtio.secure_write_string import secure_write_string

from clustermanagementtoolkit.cmtio_yaml.ruyaml_dump_to_string import ruyaml_dump_to_string

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def secure_write_yaml(path: FilePath, data: dict | list[dict]
                      | ruyaml.comments.CommentedMap | ruyaml.comments.CommentedSeq,
                      **kwargs: Any) -> None:
    """
    Dump a dict to a file in YAML-format in a safe manner.

        Parameters:
            path (FilePath): The path to write to
            data (dict|[dict]): The dict to dump
            **kwargs (dict[str, Any]): Keyword arguments
                permissions (int): File permissions (None uses system defaults)
                replace_empty (bool): True strips empty strings
                replace_empty_dict (bool): True strips empty dicts
                replace_null (bool): True strips null
                write_mode (str): [w, a, x] Write, Append, Exclusive Write
                temporary (bool): Is the file a tempfile?
                                  If so we need to disable the check for parent permissions
        Raises:
            cmttypes.FilePathAuditError
    """
    permissions: int | None = deep_get(kwargs, DictPath("permissions"))
    replace_empty: bool = deep_get(kwargs, DictPath("replace_empty"), False)
    replace_empty_dict: bool = deep_get(kwargs, DictPath("replace_empty_dict"), False)
    replace_null: bool = deep_get(kwargs, DictPath("replace_null"), False)
    write_mode: str = deep_get(kwargs, DictPath("write_mode"), "w")
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)
    yaml_version: tuple[int, int] = deep_get(kwargs, DictPath("yaml_version"))

    if write_mode not in ("a", "w", "x"):
        raise ValueError(f"Invalid write mode “{write_mode}“; "
                         "permitted modes: “a“ (append), “w“ (write) and “x“ (exclusive write)")

    yaml_str = ruyaml_dump_to_string(data, default_flow_style=False,
                                     replace_null=replace_null,
                                     replace_empty=replace_empty,
                                     replace_empty_dict=replace_empty_dict,
                                     yaml_version=yaml_version)
    secure_write_string(path, yaml_str, permissions=permissions,
                        write_mode=write_mode, temporary=temporary)
