# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A context for PoolManagers.
"""

import ssl
import sys
from typing import Any

try:
    import urllib3
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import urllib3; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install urllib3`; aborting.")

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

# Acceptable ciphers
CIPHERS: list[str] = [
    # TLS v1.3
    "TLS_AES_256_GCM_SHA384",
    # TLS v1.2
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
]


class PoolManagerContext:
    """
    A class for wrapping PoolManager/ProxyManager.
    """

    def __init__(self, cert_file: str | None = None, key_file: str | None = None,
                 ca_certs_file: str | None = None, token: str | None = None,
                 insecuretlsskipverify: bool = False) -> None:
        self.pool_manager: urllib3.ProxyManager | urllib3.PoolManager | None = None
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_certs_file = ca_certs_file
        self.token = token
        self.insecuretlsskipverify = insecuretlsskipverify

    def __enter__(self) -> urllib3.ProxyManager | urllib3.PoolManager:
        # Only permit a limited set of acceptable ciphers
        ssl_context = urllib3.util.ssl_.create_urllib3_context(ciphers=":".join(CIPHERS))
        # Disable anything older than TLSv1.2
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        # This isn't ideal; we might need different cluster proxies for different clusters
        pool_manager_proxy = deep_get(cmtlib.cmtconfig, DictPath("Network#cluster_https_proxy"), "")

        if self.cert_file is not None:
            if not self.insecuretlsskipverify:
                pool_manager_args = {
                    "cert_reqs": "CERT_REQUIRED",
                    "ca_certs": self.ca_certs_file,
                    "cert_file": self.cert_file,
                    "key_file": self.key_file,
                    "ssl_context": ssl_context,
                }
            else:
                pool_manager_args = {
                    "cert_reqs": "CERT_NONE",
                    "ca_certs": None,
                    "cert_file": self.cert_file,
                    "key_file": self.key_file,
                }
        elif self.token is not None:
            if not self.insecuretlsskipverify:
                pool_manager_args = {
                    "cert_reqs": "CERT_REQUIRED",
                    "ca_certs": self.ca_certs_file,
                    "ssl_context": ssl_context,
                }
            else:
                pool_manager_args = {
                    "cert_reqs": "CERT_NONE",
                    "ca_certs": None,
                }
        else:
            raise ProgrammingError(f"{__name__}() called with both cert_file and token == None")

        # The type ignores are necessary because mypy cannot handle
        # def foo(a: int = 5, **kwargs)
        # foo(**kwarg_dict)
        # properly; it'll try to map kwarg_dict positionally
        if pool_manager_proxy:
            self.pool_manager = urllib3.ProxyManager(pool_manager_proxy,
                                                     **pool_manager_args)  # type: ignore
        else:
            self.pool_manager = urllib3.PoolManager(**pool_manager_args)  # type: ignore

        return self.pool_manager

    def __exit__(self, *args: object, **kwargs: Any) -> None:
        if self.pool_manager is not None:
            self.pool_manager.clear()
        self.pool_manager = None
