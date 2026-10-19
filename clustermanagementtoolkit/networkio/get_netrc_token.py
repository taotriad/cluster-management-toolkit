# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the netrc bearer token matching the specied URL.
"""

import re

from clustermanagementtoolkit.cmtpaths import NETRC_PATH


def get_netrc_token(url: str | None) -> str | None:
    """
    Given a URL, check whether there's a matching bearer token in .netrc,
    and if so, return it.

        Parameters:
            url (str): The URL to find a bearer token for
        Returns:
            (str): A bearer token, or an empty string if no matching token could be found
    """
    token: str | None = None

    if url is None or not url.startswith(("http://", "https://")):
        return token

    base_url: str = url.removeprefix("http://").removeprefix("https://").split("/", maxsplit=1)[0]

    netrc_lines: list[str] = []

    try:
        with open(NETRC_PATH, "r", encoding="utf-8") as f:
            netrc_lines = f.readlines()
    except FileNotFoundError:
        return token

    is_machine: bool = False

    for line in netrc_lines:
        if (re_tmp := re.match(r"^(machine|password)\s(.+)$", line.strip())) is not None:
            if re_tmp[1] == "machine" and re_tmp[2] == base_url:
                is_machine = True
                continue
            if re_tmp[1] == "password" and is_machine:
                token = re_tmp[2]
                break
    return token
