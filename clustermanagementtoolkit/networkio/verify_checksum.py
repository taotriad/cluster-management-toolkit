# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Verify checksums.
"""

from collections.abc import Callable
import hashlib
import re

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


checksum_functions: dict[str, Callable] = {
    "md5": hashlib.md5,  # nosec
    "sha": hashlib.sha1,  # nosec
    "sha1": hashlib.sha1,  # nosec
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "shake_128": hashlib.shake_128,
    "shake_256": hashlib.shake_256,
}


def verify_checksum(checksum: bytes,
                    checksum_type: str, data: bytes, filename: str | None = None) -> bool:
    """
    Checksum data against a checksum file

        Parameters:
            checksum (bytes): The downloaded checksum file
            checksum_type (str): What hash should be used when calculating the checksum?
            data (bytes): The data to calculate the checksum of
            filename (str): Used to identify the correct checksum entry
                            in a file with multiple checksums (optional)
        Returns:
            (bool): True if the checksum matches,
                    False if the checksum does not match
    """
    if checksum_type is None:
        ansithemeprint([ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(": No checksum type provided; checksum ", "default"),
                        ANSIThemeStr("not", "emphasis"),
                        ANSIThemeStr(" verified", "default")], stderr=True)
        return True

    if (hashfun := deep_get(checksum_functions, DictPath(f"{checksum_type}"))) is None:
        return False

    if checksum_type == "md5":
        ansithemeprint([ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(": Use of MD5 checksums is ", "default"),
                        ANSIThemeStr("strongly", "emphasis"),
                        ANSIThemeStr(" discouraged", "default")], stderr=True)
    elif checksum_type in ("sha", "sha1"):
        ansithemeprint([ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(": Use of SHA1 checksums is ", "default"),
                        ANSIThemeStr("strongly", "emphasis"),
                        ANSIThemeStr(" discouraged", "default")], stderr=True)

    m = hashfun()
    m.update(data)

    # If filename is supplied it is expected that the checksum file can contain
    # more than one checksum, or at least that it contains a filename;
    # if so we find the matching entry
    regex: re.Pattern[str] = re.compile(r"^([0-9a-f]+)\s+(\S+)$")
    match_checksum = None

    for line in checksum.decode("utf-8", errors="replace").splitlines():
        if filename is None and " " not in line:
            match_checksum = line
            break

        if (re_tmp := regex.match(line)) is not None:
            if filename and re_tmp[2] != filename:
                continue
            match_checksum = re_tmp[1]
            break

    if match_checksum is None:
        return False

    if checksum_type in ("shake_128", "shake_256"):
        shake_length = len(match_checksum) // 2
        if m.hexdigest(shake_length) != match_checksum:
            return False
    else:
        if m.hexdigest() != match_checksum:
            return False

    return True
