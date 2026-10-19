# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import base64
import binascii


def decode_value(value: str | bytes) -> tuple[str, str | bytes]:
    """
    Given a value attempt to decode it from base64.

        Parameters:
            value (str | bytes): The value to decode
        Returns:
            (str, str | bytes):
                (str): The identified type
                (str | bytes): The decoded value
    """
    # Is this base64?
    try:
        decoded = base64.b64decode(value)
        vtype = "base64"
    except binascii.Error:
        vtype = "string"

    if vtype == "base64":
        try:
            tmp = decoded.decode("utf-8", errors="strict")
            if "\n" in tmp:
                vtype = "base64-utf-8"
            else:
                vtype = "string"
                value = tmp
        except UnicodeDecodeError:
            vtype = "base64-binary"

            try:
                if len(decoded) >= 2 and bytes(decoded[0:2]) == bytes([0x1f, 0x8b]):
                    vtype = "gzip"
                    value = decoded
                elif len(decoded) >= 6 and bytes(decoded[0:6]) == bytes([0xfd, 0x37, 0x7a,
                                                                         0x58, 0x5a, 0x0]):
                    vtype = "xz"
                    value = decoded
                elif len(decoded) >= 3 and bytes(decoded[0:3]) == bytes([0x42, 0x5a, 0x68]):
                    vtype = "bz2"
                    value = decoded
                elif len(decoded) >= 3 and bytes(decoded[0:3]) == bytes([0x51, 0x46, 0x49]):
                    vtype = "qcow"
                    value = decoded
            except binascii.Error:
                pass
    return vtype, value
