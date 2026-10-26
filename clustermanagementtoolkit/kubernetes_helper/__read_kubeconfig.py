# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper for reading the Kubeconfig file.
"""

import sys
from typing import Any, cast

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

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmtpaths import KUBE_CONFIG_FILE

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError


def __read_kubeconfig(config_path: FilePath | None = None) -> dict[str, Any]:
    if config_path is None:
        # Read kubeconfig
        config_path = KUBE_CONFIG_FILE

    kubeconfig: dict = {}

    try:
        kubeconfig = cast(dict, secure_read_yaml(FilePath(config_path)))
    except FileNotFoundError:
        errmsg: list[list[tuple[str, str]]] = [
            [("FileNotFoundError occurred when ", "default"),
             ("loading file ", "default"),
             (f"{config_path}", "path"),
             (".", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.WARNING, msg=unformatted_msg, messages=formatted_msg)
    except FilePathAuditError as e:
        # This matches both DOES_NOT_EXIST and PARENT_DOES_NOT_EXIST
        if "DOES_NOT_EXIST" in str(e):
            errmsg = [
                [("FileNotFoundError occurred when ", "default"),
                 ("loading file ", "default"),
                 (f"{config_path}", "path"),
                 (".", "default")],
            ]
            severity = LogLevel.WARNING
        else:
            errmsg = [
                [("FilePathAuditError", "critical"),
                 (": ", "default"),
                 (f"{e}", "errorvalue"),
                 (" when loading file ", "default"),
                 (f"{config_path}", "path"),
                 (".", "default")],
                [("Refusing to load file.", "default")],
            ]
            severity = LogLevel.ERR
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(severity, msg=unformatted_msg, messages=formatted_msg)
    except ruyaml.composer.ComposerError as e:
        errmsg = [
            [("ruyaml.composer.ComposerError: ", "default"),
             (f"{e}", "errorvalue"),
             (" encountered when parsing ", "default"),
             (f"{config_path}", "path"),
             (".", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
    except ruyaml.scanner.ScannerError as e:
        errmsg = [
            [("ruyaml.scanner.ScannerError: ", "default"),
             (f"{e}", "errorvalue"),
             (" encountered when parsing ", "default"),
             (f"{config_path}", "path"),
             (".", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
    return kubeconfig
