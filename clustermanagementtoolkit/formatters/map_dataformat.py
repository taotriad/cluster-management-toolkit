# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Mapping between filename and formatter to use.
"""

from collections.abc import Callable

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.format_ansible import format_ansible
from clustermanagementtoolkit.formatters.format_caddyfile import format_caddyfile
from clustermanagementtoolkit.formatters.format_cel import format_cel
from clustermanagementtoolkit.formatters.format_crt import format_crt
from clustermanagementtoolkit.formatters.format_css import format_css
from clustermanagementtoolkit.formatters.format_diff import format_diff
from clustermanagementtoolkit.formatters.format_dmesg import format_dmesg
from clustermanagementtoolkit.formatters.format_docker import format_docker
from clustermanagementtoolkit.formatters.format_fluentbit import format_fluentbit
from clustermanagementtoolkit.formatters.format_go import format_go
from clustermanagementtoolkit.formatters.format_haproxy import format_haproxy
from clustermanagementtoolkit.formatters.format_html import format_html
from clustermanagementtoolkit.formatters.format_ini import format_ini
from clustermanagementtoolkit.formatters.format_javascript import format_javascript
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
from clustermanagementtoolkit.formatters.render_markdown import render_markdown


# (startswith, endswith, formatter)
formatter_mapping: tuple[tuple[tuple[str, ...], tuple[str, ...], Callable], ...] = (
    (("ansible",), ("ansible",), format_ansible),
    (("shell",), ("shell",), format_shellscript),
    (("shell script",), ("shell script",), format_shellscript),
    (("",), (".sh",), format_shellscript),
    (("",), (".bash",), format_shellscript),
    (("bash",), ("bash",), format_shellscript),
    (("",), (".diff",), format_diff),
    (("",), (".patch",), format_diff),
    (("diff",), ("diff",), format_diff),
    (("",), (".dmesg",), format_dmesg),
    (("",), (".kmsg",), format_dmesg),
    (("dmesg",), ("dmesg",), format_dmesg),
    (("",), (".docker",), format_docker),
    (("",), ("dockerfile",), format_docker),
    (("docker",), ("docker",), format_docker),
    (("",), (".zsh",), format_shellscript),
    (("zsh",), ("zsh",), format_shellscript),
    (("",), (".go",), format_go),
    (("go",), ("go",), format_go),
    (("golang",), ("golang",), format_go),
    (("",), (".html",), format_html),
    (("html",), ("html",), format_html),
    (("json",), ("json",), format_yaml),
    (("ndjson",), ("ndjson",), format_yaml),
    (("yaml",), ("yaml",), format_yaml),
    (("",), (".yml", ".yaml", ".json", ".ndjson"), format_yaml),
    (("",), (".rego",), format_rego),
    (("rego",), ("rego",), format_rego),
    (("toml",), ("toml",), format_toml),
    (("",), (".toml",), format_toml),
    (("cel",), ("cel",), format_cel),
    (("",), (".cel",), format_cel),
    (("crt",), ("crt",), format_crt),
    (("",), (".crt", "tls.key", ".pem", "CAKey"), format_crt),
    (("css",), ("css",), format_css),
    (("",), (".css",), format_css),
    (("",), (".xml",), format_xml),
    (("xml",), ("xml",), format_xml),
    (("",), (".svg",), format_xml),
    (("svg",), ("svg",), format_xml),
    (("",), (".xhtml",), format_html),
    (("xhtml",), ("xhtml",), format_html),
    (("",), (".xml",), format_xml),
    (("ini",), ("ini",), format_ini),
    (("",), (".ini",), format_ini),
    (("js",), ("js",), format_javascript),
    (("javascript",), ("javascript",), format_javascript),
    (("",), (".js",), format_javascript),
    (("jws",), ("jws",), format_none),
    (("known_hosts",), ("known_hosts",), format_known_hosts),
    (("fluentbit",), ("fluentbit",), format_fluentbit),
    (("haproxy",), ("haproxy",), format_haproxy),
    (("haproxy.cfg",), ("haproxy.cfg",), format_haproxy),
    (("caddyfile",), ("caddyfile",), format_caddyfile),
    (("markdown",), ("markdown",), render_markdown),
    (("md",), ("md",), render_markdown),
    (("",), (".md",), render_markdown),
    (("mosquitto",), ("",), format_mosquitto),
    (("nginx",), ("nginx",), format_nginx),
    (("ps1",), ("ps1",), format_powershell),
    (("",), (".ps1",), format_powershell),
    (("powershell",), ("powershell",), format_powershell),
    (("",), (".promql",), format_promql),
    (("promql",), ("promql",), format_promql),
    (("python",), ("",), format_python),
    (("py",), ("py",), format_python),
    (("",), (".py",), format_python),
    (("python traceback",), ("",), format_python_traceback),
)


def map_dataformat(dataformat: str) -> Callable[[str | list[str]], list[list[ThemeRef | ThemeStr]]]:
    """
    Identify what formatter to use, based either on a file ending or an explicit dataformat tag.

        Parameters:
            dataformat: The data format *or* the name of the file
        Returns:
            (function reference): The formatter to use
    """
    for prefix, suffix, formatter_ in formatter_mapping:
        if dataformat.lower().startswith(prefix) \
                and dataformat.lower().endswith(suffix):
            return formatter_
    return format_none
