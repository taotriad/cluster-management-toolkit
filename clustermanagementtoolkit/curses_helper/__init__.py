# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Curses-based User Interface helpers.
"""

from clustermanagementtoolkit.curses_helper.alert import alert
from clustermanagementtoolkit.curses_helper.clear_tagged_items import clear_tagged_items
from clustermanagementtoolkit.curses_helper.color_log_severity import color_log_severity
from clustermanagementtoolkit.curses_helper.color_status_group import color_status_group
from clustermanagementtoolkit.curses_helper.confirmationbox import confirmationbox
from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration
from clustermanagementtoolkit.curses_helper.format_helptext import format_helptext
from clustermanagementtoolkit.curses_helper.generate_heatmap import generate_heatmap
from clustermanagementtoolkit.curses_helper.get_labels import get_labels
from clustermanagementtoolkit.curses_helper.get_mousemask import get_mousemask
from clustermanagementtoolkit.curses_helper.get_tagged_items import get_tagged_items
from clustermanagementtoolkit.curses_helper.get_tagged_objects import get_tagged_objects
from clustermanagementtoolkit.curses_helper.get_theme_ref import get_theme_ref
from clustermanagementtoolkit.curses_helper.init_curses import init_curses
from clustermanagementtoolkit.curses_helper.inputbox import inputbox
from clustermanagementtoolkit.curses_helper.in_tagged_items import in_tagged_items
from clustermanagementtoolkit.curses_helper.map_key import map_key
from clustermanagementtoolkit.curses_helper.notice import notice
from clustermanagementtoolkit.curses_helper.percentagebar import percentagebar
from clustermanagementtoolkit.curses_helper.progressbar import progressbar
from clustermanagementtoolkit.curses_helper.read_theme import read_theme
from clustermanagementtoolkit.curses_helper.scrollbar_horizontal import scrollbar_horizontal
from clustermanagementtoolkit.curses_helper.scrollbar_vertical import scrollbar_vertical
from clustermanagementtoolkit.curses_helper.set_mousemask import set_mousemask
from clustermanagementtoolkit.curses_helper.tag_item import tag_item
from clustermanagementtoolkit.curses_helper.themearray_compact import themearray_compact
from clustermanagementtoolkit.curses_helper.themearray_detab import themearray_detab
from clustermanagementtoolkit.curses_helper.themearray_flatten import themearray_flatten
from clustermanagementtoolkit.curses_helper.themearray_len import themearray_len
from clustermanagementtoolkit.curses_helper.themearray_lstrip import themearray_lstrip
from clustermanagementtoolkit.curses_helper.themearray_replace import themearray_replace
from clustermanagementtoolkit.curses_helper.themearray_rstrip import themearray_rstrip
from clustermanagementtoolkit.curses_helper.themearray_select import themearray_select
from clustermanagementtoolkit.curses_helper.themearray_split import themearray_split
from clustermanagementtoolkit.curses_helper.themearray_strip import themearray_strip
from clustermanagementtoolkit.curses_helper.themearray_to_string import themearray_to_string
from clustermanagementtoolkit.curses_helper.themearray_truncate import themearray_truncate
from clustermanagementtoolkit.curses_helper.themearray_wrap_line import themearray_wrap_line
from clustermanagementtoolkit.curses_helper.themestr import ThemeArray
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration
from clustermanagementtoolkit.curses_helper.curses_helper_types import WidgetLineAttrs
from clustermanagementtoolkit.curses_helper.uiprops import UIProps
from clustermanagementtoolkit.curses_helper.uiprops import windowwidget
from clustermanagementtoolkit.curses_helper.untag_item import untag_item
from clustermanagementtoolkit.curses_helper.window_tee_hline import window_tee_hline
from clustermanagementtoolkit.curses_helper.window_tee_vline import window_tee_vline

__all__ = [
    "CursesConfiguration",
    "ThemeArray",
    "ThemeAttr",
    "ThemeRef",
    "ThemeStr",
    "ThemeStrConfiguration",
    "UIProps",
    "WidgetLineAttrs",
    "alert",
    "clear_tagged_items",
    "color_log_severity",
    "color_status_group",
    "confirmationbox",
    "format_helptext",
    "generate_heatmap",
    "get_labels",
    "get_mousemask",
    "get_tagged_items",
    "get_tagged_objects",
    "get_theme_ref",
    "in_tagged_items",
    "init_curses",
    "inputbox",
    "map_key",
    "notice",
    "percentagebar",
    "progressbar",
    "read_theme",
    "scrollbar_horizontal",
    "scrollbar_vertical",
    "set_mousemask",
    "tag_item",
    "themearray_compact",
    "themearray_detab",
    "themearray_flatten",
    "themearray_len",
    "themearray_lstrip",
    "themearray_replace",
    "themearray_rstrip",
    "themearray_select",
    "themearray_split",
    "themearray_strip",
    "themearray_to_string",
    "themearray_truncate",
    "themearray_wrap_line",
    "untag_item",
    "window_tee_hline",
    "window_tee_vline",
    "windowwidget",
]
