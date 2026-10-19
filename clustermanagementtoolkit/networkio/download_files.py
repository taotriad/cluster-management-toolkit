# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Download and extract files in a secure manner.
"""

from collections.abc import Sequence
import errno
from getpass import getuser
import io
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile
import time

try:
    import urllib3
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import urllib3; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install urllib3`; aborting.")

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


from clustermanagementtoolkit.networkio.get_netrc_token import get_netrc_token
from clustermanagementtoolkit.networkio.verify_checksum import verify_checksum


# download_files can extract single files from archives;
# it will not extract entire archives due to the security risks,
# and it requires the full path of the file within the archive to be specified.
# If later necessary this function could be modified
# to take a list of multiple files to extract from one tarball;
# for now this does what is necessary though.
#
# fetch_urls is a list of tuples:
# (URL to file or archive, file to extract, URL to checksum, type of checksum)

# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def download_files(directory: str,
                   fetch_urls: Sequence[tuple[str, str, str | None, str | None]],
                   permissions: int = 0o644) -> bool:
    """
    Download files; if the file is a tar file it can extract a file.
    If checksum information is provided it can also fetch a checksum and compare against.

        Parameters:
            directory (str): The path to extract the file to
            fetch_urls ([(str, str, str, str)]):
                (str): The URL to download
                (str): The name of the downloaded file
                (str): The URL to the checksum
                (str): The type of checksum
            permissions (int): File permissions (*PLEASE* use octal!)
        Returns:
            (bool): True on success, False on failure
    """
    user = getuser()

    # First check that the destination directory is safe; it has to be owned by the user,
    # and other must not have write permissions; also path must resolve to itself to avoid
    # symlink attacks, and it must be a directory
    path = Path(directory)
    resolved_path = path.resolve()
    if path != resolved_path:
        ansithemeprint([ANSIThemeStr("Critical", "critical"),
                        ANSIThemeStr(": The target path ", "default"),
                        ANSIThemeStr(f"{directory}", "path"),
                        ANSIThemeStr(" does not resolve to itself; "
                                     "this is either a configuration error "
                                     "or a security issue; aborting.", "default")],
                       stderr=True)
        sys.exit(errno.EINVAL)

    if path.owner() != user:
        ansithemeprint([ANSIThemeStr("Error", "error"),
                        ANSIThemeStr(": The target path ", "default"),
                        ANSIThemeStr(f"{directory}", "path"),
                        ANSIThemeStr(" is not owned by ", "default"),
                        ANSIThemeStr(user, "emphasis"),
                        ANSIThemeStr("; aborting.", "default")], stderr=True)
        sys.exit(errno.EINVAL)

    path_stat = path.stat()
    path_permissions = path_stat.st_mode & 0o002

    if path_permissions:
        ansithemeprint([ANSIThemeStr("Critical", "critical"),
                        ANSIThemeStr(": The target path ", "default"),
                        ANSIThemeStr(f"{directory}", "path"),
                        ANSIThemeStr(" is world writable", "default"),
                        ANSIThemeStr("; aborting.", "default")], stderr=True)
        sys.exit(errno.EINVAL)

    if not path.is_dir():
        ansithemeprint([ANSIThemeStr("Error", "error"),
                        ANSIThemeStr(": The target path ", "default"),
                        ANSIThemeStr(f"{directory}", "path"),
                        ANSIThemeStr(" is not a directory", "default"),
                        ANSIThemeStr("; aborting.", "default")], stderr=True)
        sys.exit(errno.EINVAL)

    # OK, the destination is not a symlink and does not contain ".." or similar,
    # it is owned by the user, and is an existing directory; we can safely continue

    http_proxy = deep_get(cmtlib.cmtconfig, DictPath("Network#http_proxy"), "")
    https_proxy = deep_get(cmtlib.cmtconfig, DictPath("Network#https_proxy"), "")
    retval = True

    if http_proxy is not None and http_proxy != "":
        pm = urllib3.ProxyManager(http_proxy)
    else:
        pm = urllib3.PoolManager()  # type: ignore
    if https_proxy is not None and https_proxy != "":
        spm = urllib3.ProxyManager(https_proxy)
    else:
        spm = urllib3.PoolManager()  # type: ignore

    for url, filename, checksum_url, checksum_type in fetch_urls:
        header_params: dict[str, str] = {}

        # If the URL has a token in .netrc, use it for the download; this can help alleviate
        # rate-limiting for api.github.com, possibly also other sites.
        if token := get_netrc_token(checksum_url):
            header_params["Authorization"] = f"Bearer {token}"
        else:
            # If we do not have a token we rate limit.
            time.sleep(1)

        # If there's a checksum file, download it first.
        checksum = None

        if checksum_url is not None:
            if checksum_url.startswith("http://"):
                r1 = pm.request("GET", checksum_url, headers=header_params)
            elif checksum_url.startswith("https://"):
                r1 = spm.request("GET", checksum_url, headers=header_params)
            else:
                ansithemeprint([ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(": Unknown or missing protocol; "
                                             "Checksum URL ", "default"),
                                ANSIThemeStr(f"{checksum_url}", "uri")], stderr=True)
                retval = False
                break

            if r1.status == 200:
                checksum = r1.data
            else:
                retval = False
                break

        header_params = {}

        # If the URL has a token in .netrc, use it for the download; this can help alleviate
        # rate-limiting for api.github.com, possibly also other sites.
        if token := get_netrc_token(url):
            header_params["Authorization"] = f"Bearer {token}"

        try:
            if url.startswith("http://"):
                r1 = pm.request("GET", url, headers=header_params)
            elif url.startswith("https://"):
                r1 = spm.request("GET", url, headers=header_params)
            else:
                ansithemeprint([ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(": Unknown or missing protocol; URL ", "default"),
                                ANSIThemeStr(f"{url}", "uri")], stderr=True)
                retval = False
                continue
        except urllib3.exceptions.MaxRetryError as e:
            if "No route to host" in str(e):
                ansithemeprint([ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(": No route to host; URL ", "default"),
                                ANSIThemeStr(f"{url}", "uri")], stderr=True)
                retval = False
                continue
            if "Name or service not known" in str(e):
                if (re_tmp := re.match(r"^.*Failed to resolve \'(.+?)\'.*$", str(e))) is not None:
                    stripped_proxy = "[THISWILLNOTMATCH]"
                    if https_proxy:
                        stripped_proxy = https_proxy.removeprefix("http://")
                        stripped_proxy = stripped_proxy.removeprefix("https://").split(":")[0]
                    if stripped_proxy == re_tmp[1]:
                        ansithemeprint([ANSIThemeStr("Error", "error"),
                                        ANSIThemeStr(": Could not connect to ", "default"),
                                        ANSIThemeStr("https_proxy=", "default"),
                                        ANSIThemeStr(f"{https_proxy}", "uri"),
                                        ANSIThemeStr("; retry later or modify your ", "default"),
                                        ANSIThemeStr("configuration; aborting.", "default")],
                                       stderr=True)
                        sys.exit(errno.ENOENT)
                    else:
                        ansithemeprint([ANSIThemeStr("Error", "error"),
                                        ANSIThemeStr(": Name or service not known; ", "default"),
                                        ANSIThemeStr("URL ", "default"),
                                        ANSIThemeStr(f"{re_tmp[1]}", "uri")], stderr=True)
                else:
                    ansithemeprint([ANSIThemeStr("Error", "error"),
                                    ANSIThemeStr(": Name or service not known; URL ", "default"),
                                    ANSIThemeStr(f"{url}", "uri")], stderr=True)
                retval = False
                continue
            raise

        if r1.status == 200:
            # Check that we actually got any data
            if not r1.data:
                ansithemeprint([ANSIThemeStr("Critical", "error"),
                                ANSIThemeStr(": File downloaded from ", "default"),
                                ANSIThemeStr(f"{url}", "uri"),
                                ANSIThemeStr(" is empty; aborting.", "default")], stderr=True)
                retval = False
                break

            # If we have a checksum we need to confirm that the downloaded file matches the checksum
            if checksum is not None and \
                    checksum_type is not None and \
                    not verify_checksum(checksum, checksum_type, r1.data, os.path.basename(url)):
                ansithemeprint([ANSIThemeStr("Critical", "error"),
                                ANSIThemeStr(": File downloaded from ", "default"),
                                ANSIThemeStr(f"{url}", "uri"),
                                ANSIThemeStr(" did not match its expected checksum; "
                                             "aborting.", "default")], stderr=True)
                retval = False
                break

            fname: str = ""
            # NamedTemporaryFile with delete = False will create a temporary file
            # owned by user with 0o600 permissions.
            with tempfile.NamedTemporaryFile(delete=False) as f:
                biodata = io.BytesIO(r1.data)

                if tarfile.is_tarfile(biodata):
                    with tarfile.open(fileobj=biodata) as tf:
                        members = tf.getnames()
                        if filename not in members:
                            ansithemeprint([ANSIThemeStr("Critical", "critical"),
                                            ANSIThemeStr(": ", "default"),
                                            ANSIThemeStr(f"{filename}", "path"),
                                            ANSIThemeStr(" is not a part of archive; "
                                                         "aborting.", "default")], stderr=True)
                            sys.exit(errno.ENOENT)

                        with tf.extractfile(filename) as tff:  # type: ignore
                            f.write(tff.read())
                else:
                    f.write(r1.data)
                fname = f.name
            # Here we change to the permissions we are supposed to use
            os.chmod(fname, permissions)
            # Here we atomically move it in place
            shutil.move(fname, f"{directory}/{filename}")
        else:
            reason = []
            if r1.reason is not None:
                reason = [ANSIThemeStr(" (reason: ", "default"),
                          ANSIThemeStr(f"{r1.reason}", "emphasis"),
                          ANSIThemeStr(")", "default")]
            ansithemeprint([ANSIThemeStr("Error ", "error"),
                            ANSIThemeStr(": Failed to fetch URL ", "default"),
                            ANSIThemeStr(f"{url}", "uri"),
                            ANSIThemeStr("; HTTP code: ", "default"),
                            ANSIThemeStr(f"{r1.status}", "errorvalue")] + reason, stderr=True)
            retval = False
            continue
    pm.clear()
    spm.clear()

    return retval
