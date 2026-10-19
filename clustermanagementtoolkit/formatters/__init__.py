# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format text as themearrays
"""

from collections.abc import Callable

from clustermanagementtoolkit.formatters.format_ansible import format_ansible
from clustermanagementtoolkit.formatters.format_binary import format_binary
from clustermanagementtoolkit.formatters.format_caddyfile import format_caddyfile
from clustermanagementtoolkit.formatters.format_cel import format_cel
from clustermanagementtoolkit.formatters.format_crt import format_crt
from clustermanagementtoolkit.formatters.format_css import format_css
from clustermanagementtoolkit.formatters.format_diff import format_diff
from clustermanagementtoolkit.formatters.format_dmesg import format_dmesg
from clustermanagementtoolkit.formatters.format_docker import format_docker
from clustermanagementtoolkit.formatters.format_fluentbit import format_fluentbit
from clustermanagementtoolkit.formatters.format_generic import format_generic
from clustermanagementtoolkit.formatters.format_go import format_go
from clustermanagementtoolkit.formatters.format_haproxy import format_haproxy
from clustermanagementtoolkit.formatters.format_html import format_html
from clustermanagementtoolkit.formatters.format_ini import format_ini
from clustermanagementtoolkit.formatters.format_javascript import format_javascript
from clustermanagementtoolkit.formatters.format_key_value import format_key_value
from clustermanagementtoolkit.formatters.format_known_hosts import format_known_hosts
from clustermanagementtoolkit.formatters.format_mosquitto import format_mosquitto
from clustermanagementtoolkit.formatters.format_nginx import format_nginx
from clustermanagementtoolkit.formatters.format_none import format_none
from clustermanagementtoolkit.formatters.format_powershell import format_powershell
from clustermanagementtoolkit.formatters.format_promql import format_promql
from clustermanagementtoolkit.formatters.format_python import format_python
from clustermanagementtoolkit.formatters.format_python_traceback import format_python_traceback
from clustermanagementtoolkit.formatters.format_rego import format_rego
from clustermanagementtoolkit.formatters.format_shellscript import format_shellscript
from clustermanagementtoolkit.formatters.format_toml import format_toml
from clustermanagementtoolkit.formatters.format_xml import format_xml
from clustermanagementtoolkit.formatters.format_yaml import format_yaml
from clustermanagementtoolkit.formatters.identify_data import cmdata_format
from clustermanagementtoolkit.formatters.identify_data import identify_cmdata
from clustermanagementtoolkit.formatters.identify_data import identify_formatter
from clustermanagementtoolkit.formatters.map_dataformat import map_dataformat
from clustermanagementtoolkit.formatters.reformat_json import reformat_json
from clustermanagementtoolkit.formatters.render_markdown import render_markdown

__all__ = [
    "cmdata_format",
    "format_ansible",
    "format_binary",
    "format_caddyfile",
    "format_cel",
    "format_crt",
    "format_css",
    "format_diff",
    "format_dmesg",
    "format_docker",
    "format_fluentbit",
    "format_generic",
    "format_go",
    "format_haproxy",
    "format_html",
    "format_ini",
    "format_javascript",
    "format_key_value",
    "format_known_hosts",
    "format_mosquitto",
    "format_nginx",
    "format_none",
    "format_powershell",
    "format_promql",
    "format_python",
    "format_python_traceback",
    "format_rego",
    "format_shellscript",
    "format_toml",
    "format_xml",
    "format_yaml",
    "identify_cmdata",
    "identify_formatter",
    "map_dataformat",
    "reformat_json",
    "render_markdown",
]

# Formatters acceptable for direct use in view files
formatter_allowlist: dict[str, Callable] = {
    "format_ansible": format_ansible,
    "format_autodetect": map_dataformat,
    "format_caddyfile": format_caddyfile,
    "format_cel": format_cel,
    "format_crt": format_crt,
    "format_css": format_css,
    "format_diff": format_diff,
    "format_docker": format_docker,
    "format_fluentbit": format_fluentbit,
    "format_generic": format_generic,
    "format_go": format_go,
    "format_haproxy": format_haproxy,
    "format_html": format_html,
    "format_ini": format_ini,
    "format_javascript": format_javascript,
    "format_key_value": format_key_value,
    "format_known_hosts": format_known_hosts,
    "format_mosquitto": format_mosquitto,
    "format_nginx": format_nginx,
    "format_none": format_none,
    "format_powershell": format_powershell,
    "format_promql": format_promql,
    "format_python": format_python,
    "format_python_traceback": format_python_traceback,
    "format_rego": format_rego,
    "format_shellscript": format_shellscript,
    "format_toml": format_toml,
    "format_xml": format_xml,
    "format_yaml": format_yaml,
    "identify_cmdata": identify_cmdata,
    "identify_formatter": identify_formatter,
    "reformat_json": reformat_json,
    "render_markdown": render_markdown,
}
