# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper that attempts to identify the formatter to use for data.
"""

import base64
import binascii
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from clustermanagementtoolkit.cmtio_yaml.secure_read_yaml import secure_read_yaml

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import split_msg

from clustermanagementtoolkit.cmtpaths import HOMEDIR
from clustermanagementtoolkit.cmtpaths import PARSERS_DIR
from clustermanagementtoolkit.cmtpaths import SYSTEM_PARSERS_DIR

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError

from clustermanagementtoolkit.formatters.format_binary import format_binary
from clustermanagementtoolkit.formatters.format_none import format_none
from clustermanagementtoolkit.formatters.map_dataformat import map_dataformat

# pylint: disable-next=pointless-string-statement
"""
Signatures used to detect format for ConfigMaps.
These signatures are based on the names of the ConfigMap and its data.

Fields, in order:
    Data Format
    ConfigMap Namespace
    ConfigMap Name (prefix)
    ConfigMap Name (suffix)
    ConfigMap Data Name (prefix)
    ConfigMap Data Name (suffix)

To do an exact match you can set prefix == suffix.
Note: This *may* fail if the same substring occurs twice; first and last in the name.
"""
cmdata_format: list[tuple[str, str, str, str, str, str]] = []


# These are based on the data itself
"""
Signatures used to detect format for ConfigMaps.
These signatures are based on the data itself.

Fields, in order:
    Data Format
    Data (prefix)
"""
cmdata_header: list[tuple[str, str]] = []


"""
Signatures used to detect format for ConfigMaps.
These signatures are based on the data itself, in binary format.

Fields, in order:
    Data Format
    Offset
    Data (array)
"""
cmdata_bin_header: list[tuple[str, int, tuple[int, ...]]] = []


"""
Overrides for base64 detection; some short ASCII strings
are indistinguishable from base64; override some of the false positives
we've found.
"""
cmdata_base64_overrides: list[str] = []


# pylint: disable-next=too-many-locals,too-many-branches
def identify_cmdata(cmdata_name: str, cm_name: str,
                    cm_namespace: str, data: Any) -> tuple[str, Callable]:
    """
    Try to identify the format of a configmap given the name of the data,
    the name of the configmap, the namespace of the configmap, and the data itself.

        Parameters:
            cmdata_name (str): The name of the configmap data
            cm_name (str): The name of the configmap
            cm_namespace (str): The namespace of the configmap
            data (Any): The data
        Returns:
            (str, Callable):
                description (str): The description of the format
                formatter (Callable): The formatter to use
    """
    uudata: bool = False

    if not data:
        return "Empty", format_none

    if not cmdata_format:
        # This will populate cmdata_format, cmdata_header, and cmdata_bin_header
        _status = import_configmap_signatures()

    # For very short strings b64decode cannot tell the difference between
    # bas64 data and ASCII. Add workarounds for some very common short strings.
    if data in cmdata_base64_overrides:
        return "Text", format_none

    if "\n" not in data:
        try:
            decoded = base64.b64decode(data)
            if base64.b64encode(decoded) == bytes(data, encoding="utf-8", errors="replace"):
                uudata = True
        except binascii.Error:
            pass

    if uudata:
        try:
            int(data)
            return "Text", format_none
        except ValueError:
            pass

        try:
            data = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            for dataformat, offset, match_bin_infix in cmdata_bin_header:
                if len(decoded) < len(match_bin_infix) + offset:
                    continue

                if bytes(match_bin_infix) == decoded[offset:len(match_bin_infix) + offset]:
                    return dataformat, format_binary
            return "Text or Base64 encoded binary", format_none

    splitmsg = split_msg(data)
    dataformat = ""

    # We are in luck; there is an interpreter signature
    # or other type of signature to help.
    if splitmsg and splitmsg[0].startswith(("#!", "-----")):
        for tmp in cmdata_header:
            tmp_dataformat, match_infix = tmp
            if match_infix in data:
                dataformat = tmp_dataformat
                break

    if not dataformat:
        for tmp_dataformat, match_cm_namespace, match_cm_name_prefix, match_cm_name_suffix, \
                match_cmdata_prefix, match_cmdata_suffix in cmdata_format:
            # pylint: disable-next=too-many-boolean-expressions
            if ((not match_cm_namespace or match_cm_namespace == cm_namespace)
                    and cm_name.startswith(match_cm_name_prefix)
                    and cm_name.endswith(match_cm_name_suffix)
                    and cmdata_name.startswith(match_cmdata_prefix)
                    and cmdata_name.endswith(match_cmdata_suffix)):
                dataformat = tmp_dataformat
                break

    formatter = map_dataformat(dataformat)

    return dataformat, formatter


# pylint: disable-next=too-many-locals,too-many-branches
def import_configmap_signatures() -> StatusGroup:
    """
    Import configmap signatures and populate cmdata_format,
    cmdata_header, and cmdata_bin_header.

        Returns:
                (status): StatusGroup.OK on success, StatusGroup.WARNING
                          if file or path doesn't exist
        Raises:
            ruyaml.composer.ComposerError (synchronous mode)
            ruyaml.parser.ParserError (synchronous mode)
            ruyaml.scanner.ScannerError (synchronous mode)
            ruyaml.constructor.DuplicateKeyError (synchronous mode)
            yaml.parser.ParserError (asynchronous mode)
            cmttypes.FilePathAuditError
    """
    global cmdata_format  # pylint: disable=global-statement
    global cmdata_header  # pylint: disable=global-statement
    global cmdata_bin_header  # pylint: disable=global-statement
    global cmdata_base64_overrides  # pylint: disable=global-statement

    new_cmdata_format: list[tuple[str, str, str, str, str, str]] = []
    new_cmdata_header: list[tuple[str, str]] = []
    new_cmdata_bin_header: list[tuple[str, int, tuple[int, ...]]] = []
    status: StatusGroup = StatusGroup.OK

    d: dict[str, Any] = {}

    parser_dirs = []
    parser_dirs += deep_get(cmtlib.cmtconfig, DictPath("Pod#local_parsers"), [])
    parser_dirs.append(PARSERS_DIR)
    parser_dirs.append(SYSTEM_PARSERS_DIR)

    for parser_dir in parser_dirs:
        if parser_dir.startswith("{HOME}"):
            parser_dir = parser_dir.replace("{HOME}", HOMEDIR, 1)

        path = Path(parser_dir).joinpath("configmaps.yaml")
        if not path.is_file():
            continue

        if not cmdata_format:
            try:
                d = cast(dict, secure_read_yaml(FilePath(path),
                                                directory_is_symlink=True, asynchronous=True))
            except FilePathAuditError as e:
                if "SecurityStatus.PARENT_DOES_NOT_EXIST" in str(e) \
                        or "SecurityStatus.DOES_NOT_EXIST" in str(e):
                    status = StatusGroup.WARNING
                else:
                    raise

        cmdata_base64_overrides = deep_get(d, DictPath("base64_overrides"), [])

        for entry in deep_get(d, DictPath("configmap_signatures"), {}).values():
            format_name = deep_get(entry, DictPath("format_name"), "<unknown>")
            for signature in deep_get(entry, DictPath("signatures"), []):
                # Namespace of the ConfigMap
                namespace: str = deep_get(signature, DictPath("namespace"), "")
                # Name of the ConfigMap; prefix and suffix
                name_prefix: str = deep_get(signature, DictPath("prefix"), "")
                name_suffix: str = deep_get(signature, DictPath("suffix"), "")
                # Name of the data; prefix and suffix
                data_prefix: str = deep_get(signature, DictPath("data_prefix"), "")
                data_suffix: str = deep_get(signature, DictPath("data_suffix"), "")
                # Content of the data; string and binary
                data_header: str = deep_get(signature, DictPath("data_header"), "")
                data_offset: int = deep_get(signature, DictPath("data_header"), 0x0)
                data_binary: list[int] = deep_get(signature, DictPath("data_binary"), [])

                if any((namespace, name_prefix, name_suffix, data_prefix, data_suffix)):
                    new_cmdata_format.append((format_name, namespace, name_prefix, name_suffix,
                                              data_prefix, data_suffix))
                if data_header:
                    new_cmdata_header.append((format_name, data_header))
                if data_binary:
                    new_cmdata_bin_header.append((format_name, data_offset, tuple(data_binary)))

                # This is a catch-all.
                if not any((namespace, name_prefix, name_suffix,
                            data_prefix, data_suffix, data_header, data_binary)):
                    new_cmdata_format.append((format_name, namespace, name_prefix, name_suffix,
                                              data_prefix, data_suffix))

    if new_cmdata_format:
        cmdata_format = new_cmdata_format
        cmdata_header = new_cmdata_header
        cmdata_bin_header = new_cmdata_bin_header

    return status


def identify_formatter(dataformat: str,
                       kind: tuple[str, str] | None = None,
                       obj: dict[str, Any] | None = None,
                       path: str | None = None) -> Callable:
    """
    Identify what formatter to use for an object.

        Parameters:
            dataformat (str): [unused]
            kind ((str, str)): The kind of data
            obj (dict): The object to fetch the data from
            path (str): The path to the data to identify the formatter for
        Returns:
            (callable): A formatter
    """
    formatter = format_none

    if dataformat is None:
        if kind is not None and obj is not None and path is not None:
            if kind == ("ConfigMap", ""):
                cmdata_name = path
                cm_name = deep_get(obj, DictPath("metadata#name"))
                cm_namespace = deep_get(obj, DictPath("metadata#namespace"))
                data = deep_get(obj, DictPath(f"data#{path}"))
                dataformat, formatter = identify_cmdata(cmdata_name, cm_name, cm_namespace, data)
            else:
                raise ValueError(f"We do not know how to auto-identify data for kind {kind}")
        else:
            raise ValueError(f"{__name__}() called without dataformat, and kind, obj, or path=None")

    return formatter
