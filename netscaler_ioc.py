"""Dissect plugin: NetScaler ADC IOC hunt.

Port of the Cloud Software Group NetScaler IOC shell script plus
GTIG/Mandiant NetScaler ADC exploitation indicators published 2026-09-29.

Usage:
    target-query -f netscaler.ioc --plugin-path /path/to/dir <image>
"""

from __future__ import annotations

import gzip
import re
import stat
from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

NetscalerIocRecord = TargetRecordDescriptor(
    "application/netscaler/ioc",
    [
        ("string", "ioc_name"),
        ("string", "category"),
        ("path", "path"),
        ("varint", "line_number"),
        ("string", "match"),
        ("string", "mode"),
        ("varint", "uid"),
        ("varint", "gid"),
        ("filesize", "size"),
        ("datetime", "mtime"),
    ],
)

MAX_MATCH_LEN = 500
MAX_CONTENT_SCAN = 100 * 1024
DEFAULT_NOBODY_GID = 65534

WEB_ROOTS = [
    ("/var/netscaler/logon", False),
    ("/var/vpn", False),
    ("/netscaler/ns_gui", True),
    ("/var/netscaler/gui", True),
    ("/netscaler/portal", False),
]

# GTIG mentioned native client/plugin and web asset paths.
GTIG_STAGING_ROOTS = [
    "/var/netscaler/gui/vpn/scripts/linux",
    "/netscaler/ns_gui/vpn/scripts/linux",
    "/var/netscaler/gui/vpns/scripts/vista",
    "/var/netscaler/gui/vpns/scripts/mac",
    "/netscaler/ns_gui/vpn/media",
    "/var/vpn/theme",
]

B = lambda p: re.compile(p)  # noqa: E731

# Log/config grep rules. A source is an exact file or a log prefix.
GREP_RULES = [
    # Existing checks.
    ("Potentially suspicious files", "httpd.conf PHP handler",
     B(rb"AddHandler[ \t]+application/x-httpd-php"),
     [("file", "/etc/httpd.conf"), ("file", "/nsconfig/httpd.conf"), ("file", "/flash/nsconfig/httpd.conf")]),
    ("Potentially suspicious files", "httpaccess installer/ico request",
     B(rb"nsginstaller\.deb|nsgclient|[0-9A-Fa-f]{6}\.ico"), [("log", "/var/log/httpaccess")]),
    ("Potentially suspicious files", "httperror installer/sig request",
     B(rb"nsginstaller\.deb|nsgclient|[0-9A-Fa-f]{6}/.sig"), [("log", "/var/log/httperror")]),
    ("Potentially suspicious files", "base64 '<?php' in httpaccess",
     B(rb"PD9waHAg|PD9waHAK"), [("log", "/var/log/httpaccess")]),
    ("Potentially suspicious files", "pitboss IFS in ns.log",
     B(rb"pitboss.*IFS"), [("log", "/var/log/ns.log")]),
    ("Potentially suspicious files", "AAATM pitboss PPE in ns.log",
     B(rb"AAATM.*pitboss PPE"), [("log", "/var/log/ns.log")]),
    ("Suspicious config file alterations", "python in rc.netscaler",
     B(rb"python"), [("file", "/flash/nsconfig/rc.netscaler")]),
    ("Suspicious config file alterations", "commented 'Require all denied'",
     B(rb"# *Require all denied"), [("file", "/etc/httpd.conf"), ("file", "/nsconfig/httpd.conf")]),
    ("Suspicious config file alterations", "commented 'php_flag engine off'",
     B(rb"# *php_flag engine off"), [("file", "/etc/httpd.conf"), ("file", "/nsconfig/httpd.conf")]),
    ("Artifact removal indicators", "rm /var/core/*",
     B(rb"rm /var/core/\*"), [("log", "/var/log/notice.log"), ("log", "/var/log/sh.log"), ("log", "/var/log/bash.log")]),
    ("Suspicious memory overread", "acs=<..0xF0 CR..> in ns.log",
     B(rb"acs=<.*\xf0(?:\r|\^M).*>, for"), [("log", "/var/log/ns.log")]),
    ("Suspicious memory overread", "WSFed request_id with non-ASCII bytes",
     B(rb"WSFed: request_id.*[\x80-\xff]"), [("log", "/var/log/ns.log")]),
    ("Suspicious memory overread", "WSFed request_id with multiple '^'",
     B(rb"WSFed: request_id.*\^.*\^"), [("log", "/var/log/ns.log")]),

    # GTIG/Mandiant 2026-09-29: exploit/process telemetry.
    ("Exploitation telemetry", "DTLSv1.0 handshake failure internal error",
     B(rb"SSL_HANDSHAKE_FAILURE.*ClientVersion\s+DTLSv1\.0.*Handshake failure-Internal Error"),
     [("log", "/var/log/ns.log"), ("log", "/var/log/messages")]),
    ("Exploitation telemetry", "NSPPE process termination",
     B(rb"NSPPE-[0-9]+.*(?:exit|terminated)|NSPPE.*(?:exit|terminated).*orphan rings"),
     [("log", "/var/log/messages")]),
    ("Exploitation telemetry", "pitboss NOT restarting NSPPE",
     B(rb"pitboss.*NOT restarting NSPPE"), [("log", "/var/log/messages"), ("log", "/var/log/ns.log")]),

    # GTIG network/HTTP IOCs where the request data survived into logs.
    ("Web shell interaction", "NSC command-execution header",
     B(rb"HTTP_NSC_(?:LDAP|CLIENTTYPE)|NSC_(?:LDAP|CLIENTTYPE)"),
     [("log", "/var/log/httpaccess"), ("log", "/var/log/httperror")]),
    ("Web shell interaction", "WHIPSHOT X_UX header",
     B(rb"HTTP_X_UX(?:_[0-9]+)?"), [("log", "/var/log/httpaccess"), ("log", "/var/log/httperror")]),
    ("Web shell interaction", "NetScaler masqueraded icon URI",
     B(rb"/vpn/media/(?:nsgclient|[0-9A-Za-z_-]+)\.ico"), [("log", "/var/log/httpaccess"), ("log", "/var/log/httperror")]),
    ("Web shell interaction", "NetScaler web shell staging URI",
     B(rb"/vpn/scripts/linux/(?:nsginstaller[^/]*\.deb|nsgclient[^/]*\.deb|[^/]+\.php)"),
     [("log", "/var/log/httpaccess"), ("log", "/var/log/httperror")]),
    ("Network IOC", "GTIG reported source IP 143.198.7.94",
     B(rb"\b143\.198\.7\.94\b"), [("log", "/var/log/httpaccess"), ("log", "/var/log/httperror"), ("log", "/var/log/ns.log"), ("log", "/var/log/messages")]),
    ("Network IOC", "GTIG reported source IP 157.254.167.12",
     B(rb"\b157\.254\.167\.12\b"), [("log", "/var/log/httpaccess"), ("log", "/var/log/httperror"), ("log", "/var/log/ns.log"), ("log", "/var/log/messages")]),

    # GTIG file/config and persistence telemetry.
    ("Suspicious config file alterations", "non-PHP extension registered as PHP",
     B(rb"(?i)Add(?:Handler|Type)[ \t]+['\"]?application/x-httpd-php['\"]?[ \t]+\.(?:deb|sig|html|rpm|tgz|sh|so|dat|ico|png|[a-z0-9_-]+)"),
     [("file", "/etc/httpd.conf"), ("file", "/nsconfig/httpd.conf"), ("file", "/flash/nsconfig/httpd.conf")]),
    ("Suspicious config file alterations", "PHP engine enabled",
     B(rb"(?i)php_flag[ \t]+engine[ \t]+on"),
     [("file", "/etc/httpd.conf"), ("file", "/nsconfig/httpd.conf"), ("file", "/flash/nsconfig/httpd.conf")]),
    ("Suspicious config file alterations", "AliasMatch redirects VPN asset path",
     B(rb"(?i)AliasMatch.*(?:/vpn/?(?:s/)?(?:media|theme|themes|images|help|logon|support)/|/var/netscaler/gui/vpn(?:s)?/scripts/|/vpn(?:s)?/scripts/)"),
     [("file", "/etc/httpd.conf"), ("file", "/nsconfig/httpd.conf"), ("file", "/flash/nsconfig/httpd.conf")]),
    ("Persistence indicators", "setuid shell command",
     B(rb"chmod[ \t]+u\+s[ \t]+/bin/sh"), [("log", "/var/log/sh.log"), ("log", "/var/log/bash.log"), ("log", "/var/log/notice.log")]),
    ("Persistence indicators", "NetScaler reboot command",
     B(rb"/netscaler/nsshutdown[ \t]+-R"), [("log", "/var/log/sh.log"), ("log", "/var/log/bash.log"), ("log", "/var/log/notice.log")]),
    ("Persistence indicators", "Apache restart command",
     B(rb"(?:/bin/httpd|httpd)[ \t]+-k[ \t]+restart(?:[ \t]+-f[ \t]+/etc/httpd\.conf)?"), [("log", "/var/log/sh.log"), ("log", "/var/log/bash.log"), ("log", "/var/log/notice.log")]),
    ("Artifact removal indicators", "VPN path log-scrubbing regex",
     B(rb"#\^\.\*/vpn(?:s)?/(?:scripts|media|theme|themes|help|logon)"), [("log", "/var/log/sh.log"), ("log", "/var/log/bash.log"), ("file", "/etc/crontab")]),
]


class NetscalerIocPlugin(Plugin):
    """Hunt for Citrix NetScaler ADC compromise indicators on a disk image."""

    __namespace__ = "netscaler"

    def check_compatible(self) -> None:
        fs = self.target.fs
        if not any(fs.path(p).exists() for p in ("/netscaler", "/nsconfig", "/flash", "/var/netscaler")):
            raise UnsupportedPluginError("No NetScaler directories found on target")

    def _walk(self, root: str) -> Iterator:
        stack = [self.target.fs.path(root)]
        while stack:
            cur = stack.pop()
            try:
                entries = list(cur.iterdir())
            except Exception as e:
                self.target.log.debug("Cannot list %s: %s", cur, e)
                continue
            for entry in entries:
                yield entry
                try:
                    if entry.is_dir() and not entry.is_symlink():
                        stack.append(entry)
                except Exception:
                    continue

    def _logs(self, prefix: str) -> list:
        parent, base = prefix.rsplit("/", 1)
        try:
            return sorted(p for p in self.target.fs.path(parent).iterdir() if p.name.startswith(base) and p.is_file())
        except Exception:
            return []

    def _open_lines(self, path):
        fh = path.open("rb")
        if path.name.endswith(".gz"):
            fh = gzip.open(fh, "rb")
        return fh

    def _read_limited(self, path, limit: int = MAX_CONTENT_SCAN) -> bytes:
        with self._open_lines(path) as fh:
            return fh.read(limit)

    def _nobody_gid(self) -> int:
        try:
            group = self.target.fs.path("/etc/group")
            if group.exists():
                for line in group.read_text(errors="replace").splitlines():
                    parts = line.split(":")
                    if parts[0] == "nobody" and len(parts) > 2:
                        return int(parts[2])
        except Exception:
            pass
        return DEFAULT_NOBODY_GID

    def _file_record(self, ioc_name: str, category: str, path, st=None, match: str = "", line_number: int | None = None):
        try:
            st = st or path.lstat()
            return NetscalerIocRecord(
                ioc_name=ioc_name, category=category, path=path, line_number=line_number,
                match=match, mode=oct(st.st_mode), uid=st.st_uid, gid=st.st_gid,
                size=st.st_size, mtime=st.st_mtime, _target=self.target,
            )
        except Exception:
            return NetscalerIocRecord(ioc_name=ioc_name, category=category, path=path,
                                      line_number=line_number, match=match, _target=self.target)

    def _check_web_files(self) -> Iterator[NetscalerIocRecord]:
        for root, exclude_admin in WEB_ROOTS:
            is_gui = root == "/var/netscaler/gui"
            for p in self._walk(root):
                try:
                    if not p.is_file():
                        continue
                except Exception:
                    continue
                sp = str(p)
                name = p.name.lower()
                in_admin = exclude_admin and sp.startswith(f"{root}/admin_ui/")
                if not in_admin:
                    if name.endswith(".php"):
                        yield self._file_record("PHP file in web root", "Suspicious php files", p)
                    if name.endswith(".xhtml"):
                        yield self._file_record("xhtml file in web root", "Potentially suspicious files", p)
                if is_gui and name.endswith(".sig"):
                    yield self._file_record(".sig file in GUI dir", "Potentially suspicious files", p)
                if is_gui and name in ("nsgclient18.deb", "nsginstaller.deb"):
                    yield self._file_record("NSG installer .deb in GUI dir", "Potentially suspicious files", p)

    def _check_gtig_staging(self) -> Iterator[NetscalerIocRecord]:
        """GTIG 2026-09-29: inspect native plugin/web-asset paths for masqueraded scripts."""
        seen = set()
        for root in GTIG_STAGING_ROOTS:
            for p in self._walk(root):
                try:
                    if not p.is_file() or str(p) in seen:
                        continue
                    seen.add(str(p))
                    st = p.lstat()
                    if st.st_size > MAX_CONTENT_SCAN:
                        continue
                    data = self._read_limited(p)
                except Exception:
                    continue

                lower = data.lower()
                php = b"<?php" in lower
                dynamic = any(x in lower for x in (
                    b"eval(", b"base64_decode(", b"shell_exec(", b"system(", b"passthru(",
                    b"proc_open(", b"popen(", b"assert(",
                ))
                if php or dynamic:
                    reason = "PHP script markers in GTIG staging path" if php else "dynamic PHP execution marker in GTIG staging path"
                    yield self._file_record(reason, "Suspicious web shell content", p,
                                            match=data[:MAX_MATCH_LEN].decode("latin-1", errors="replace"))

                # WHIPSHOT YARA-equivalent subset: require C2 header plus IPC/socket evidence.
                if (b"http_x_ux" in lower and (b"/.uxdport" in lower or b"/.uxdlock" in lower)
                        and (b"fsockopen" in lower or b"127.0.0.1" in lower)):
                    yield self._file_record("WHIPSHOT PHP web shell content", "Suspicious web shell content", p)

                # SLAPSHOT YARA-equivalent subset.
                commands = sum(token in lower for token in (b'"open"', b'"conn"', b'"push"', b'"pull"', b'"exch"', b'"close"', b'"ping"'))
                params = sum(token in lower for token in (b'"sid"', b'"host"', b'"port"', b'"data"'))
                if ((b"/tmp/.uxdport" in lower and b"/tmp/.uxdlock" in lower and b"uxd_idle_exit" in lower)
                        or (b"uxd_idle_exit" in lower and commands >= 3 and params >= 2)
                        or (b"127.0.0.1" in lower and (b"/.uxdport" in lower or b"/.uxdlock" in lower) and commands >= 3 and params >= 2)):
                    yield self._file_record("SLAPSHOT Python tunneler content", "Suspicious tunneler content", p)

    def _check_ephemeral_artifacts(self) -> Iterator[NetscalerIocRecord]:
        for path in ("/tmp/.uxdport", "/tmp/.uxdlock"):
            p = self.target.fs.path(path)
            try:
                if p.exists() and p.is_file():
                    yield self._file_record("SLAPSHOT ephemeral artifact", "SLAPSHOT artifacts", p)
            except Exception:
                continue

    def _check_bin_sh_suid(self) -> Iterator[NetscalerIocRecord]:
        p = self.target.fs.path("/bin/sh")
        try:
            st = p.lstat()
            if st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
                yield self._file_record("SUID bit on /bin/sh", "setuid persistence", p, st=st)
        except Exception:
            return

    def _check_greps(self) -> Iterator[NetscalerIocRecord]:
        for category, ioc_name, rx, sources in GREP_RULES:
            paths = []
            for kind, src in sources:
                if kind == "file":
                    p = self.target.fs.path(src)
                    try:
                        if p.is_file():
                            paths.append(p)
                    except Exception:
                        pass
                else:
                    paths.extend(self._logs(src))

            seen = set()
            for path in paths:
                if str(path) in seen:
                    continue
                seen.add(str(path))
                try:
                    with self._open_lines(path) as fh:
                        for lineno, line in enumerate(fh, 1):
                            if rx.search(line):
                                text = line.rstrip(b"\r\n")[:MAX_MATCH_LEN].decode("latin-1", errors="replace")
                                yield self._file_record(ioc_name, category, path, match=text, line_number=lineno)
                except Exception as e:
                    self.target.log.warning("Failed reading %s: %s", path, e)

    @export(record=NetscalerIocRecord)
    def ioc(self) -> Iterator[NetscalerIocRecord]:
        """Yield NetScaler compromise indicators."""
        yield from self._check_web_files()
        yield from self._check_gtig_staging()
        yield from self._check_ephemeral_artifacts()
        yield from self._check_bin_sh_suid()
        yield from self._check_setuid()
        yield from self._check_greps()

    def _check_setuid(self) -> Iterator[NetscalerIocRecord]:
        nobody = self._nobody_gid()
        for root in ("/var", "/flash"):
            for p in self._walk(root):
                try:
                    if p.is_symlink():
                        continue
                    st = p.lstat()
                except Exception:
                    continue
                m = st.st_mode
                if st.st_uid != 0 or not (m & stat.S_ISUID):
                    continue
                if (m & 0o001) or ((m & 0o010) and st.st_gid == nobody):
                    yield self._file_record("setuid root file", "setuid files", p, st=st)
