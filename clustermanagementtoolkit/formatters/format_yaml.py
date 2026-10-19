# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import copy
import json
import sys
from typing import Any
try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import yaml; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install PyYAML`; aborting.")

import pygments
from pygments.lexer import Lexer
from pygments.lexers.data import JsonLexer
from pygments.lexers.data import YamlLexer

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmtio_yaml import json_dumps

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.apply_focus_filter import apply_focus_filter
from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_JSON
from clustermanagementtoolkit.formatters.colorschemes import COLORSCHEME_YAML
from clustermanagementtoolkit.formatters.format_none import format_none
from clustermanagementtoolkit.formatters.themearray_formatter import ThemeArrayFormatter
from clustermanagementtoolkit.formatters.__str_representer import __str_representer


# pylint: disable-next=too-many-branches
def format_yaml(lines: str | list[str] | dict | list[dict], **kwargs: Any) -> \
        list[list[ThemeRef | ThemeStr]]:
    """
    YAML formatter; returns the text with syntax highlighting for YAML.

        Parameters:
            lines (str|[str]|dict): A list of strings *or*
                               a string with newlines that should be split,
                               *or* a dict to dump as yaml
            **kwargs (dict[str, Any]): Keyword arguments
                is_json (bool): Is this json or yaml?
                unfold_msg (bool): Unfold the message
        Returns:
            ([themearray]): A list of themearrays
    """
    is_json: bool = deep_get(kwargs, DictPath("json"), False)
    unfold_msg: bool = deep_get(kwargs, DictPath("unfold_msg"), False)
    yaml.add_representer(str, __str_representer)

    if not lines:
        return []

    new_lines = copy.deepcopy(lines)

    if isinstance(new_lines, list) and isinstance(new_lines[0], str):
        new_lines = "\n".join(new_lines)

    if isinstance(new_lines, str):
        # If it's one single line and starts and ends with either [] or {} we try to expand it.
        if is_json or (len(new_lines.splitlines()) == 1 and new_lines.startswith(("{", "["))
                       and new_lines.rstrip().endswith(("}", "]")) and unfold_msg):
            try:
                # Treat json as YAML; in case we misidentify YAML as JSON we might
                # fail to decode the data. YAML is more forgiving. Note that this
                # may result in the file being reformatted. This isn't ideal,
                # but it's the only reliable way to be able to expand a JSON/YAML structure.
                d = yaml.safe_load(new_lines)
                d = apply_focus_filter(d, **kwargs)
                new_lines = json_dumps(d)
            except (ValueError, json.decoder.JSONDecodeError):
                pass
    elif isinstance(new_lines, dict):
        new_lines = copy.deepcopy(new_lines)
        new_lines = apply_focus_filter(new_lines, **kwargs)

        if is_json:
            new_lines = json_dumps(new_lines)
        else:
            new_lines = yaml.dump(new_lines, sort_keys=False)
    elif isinstance(new_lines, list):
        # We've already checked; we know that new_lines has data,
        # hence we can safely check the first element of the data.
        if isinstance(new_lines[0], dict):
            # When we get multiple objects it's because they're intended to be flattened
            # into the same logpad.
            lline = []
            for d in new_lines:
                d = apply_focus_filter(d, **kwargs)
                if is_json:
                    lline.append(json_dumps(d))
                else:
                    lline.append(yaml.dump(d, sort_keys=False))
            new_lines = "\n".join(lline)
        else:
            errmsg = [
                [("Cannot handle input “", "default"),
                 (f'{new_lines}', "argument"),
                 ("“.", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            return [[ThemeStr("format_yaml()", ThemeAttr("types", "python_function")),
                     ThemeStr(": Cannot handle input “", ThemeAttr("types", "generic")),
                     ThemeStr(f"{new_lines}", ThemeAttr("main", "highlight")),
                     ThemeStr("“.", ThemeAttr("types", "generic"))]]
    else:
        errmsg = [
            [("Cannot handle input “", "default"),
             (f'{new_lines}', "argument"),
             ("“.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        return [[ThemeStr("format_yaml()", ThemeAttr("types", "python_function")),
                 ThemeStr(": Cannot handle input “", ThemeAttr("types", "generic")),
                 ThemeStr(f"{new_lines}", ThemeAttr("main", "highlight")),
                 ThemeStr("“.", ThemeAttr("types", "generic"))]]

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(new_lines)

    override_formatting: dict[str, ThemeAttr] = \
        deep_get(kwargs, DictPath("override_formatting"), {})

    if is_json:
        lexer: Lexer = JsonLexer()
        formatter = ThemeArrayFormatter(colorscheme=COLORSCHEME_JSON,
                                        override_formatting=override_formatting,
                                        lexer=lexer)
    else:
        lexer = YamlLexer()
        formatter = ThemeArrayFormatter(colorscheme=COLORSCHEME_YAML,
                                        override_formatting=override_formatting,
                                        lexer=lexer)
    pygments.highlight(new_lines, lexer, formatter)

    return formatter.buffer
