"""
Sentinel Agent - Raw Log Writer
Writes every event as a plain human-readable text line.
No JSON, no CSV formatting — pure raw log.

Format:
[TIMESTAMP] [SEVERITY] [CATEGORY] [ACTION] [COLLECTOR] HOST=hostname USER=user PATH/IP=value NOTES=notes

Example:
[2024-01-15 10:23:45 UTC] [HIGH] [authentication] [login_failed] [auth_monitor] HOST=DESKTOP-ABC USER=admin IP=192.168.1.99 NOTES=Failed login attempt
[2024-01-15 10:24:01 UTC] [LOW]  [file]           [usb_connected] [usb_monitor]  HOST=DESKTOP-ABC PATH=E: LABEL=KINGSTON SERIAL=AA040217 NOTES=USB connected
"""

import threading
import gzip
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..logger import Logger

logger = Logger.get_logger(__name__)


class RawLogWriter:
    """
    Writes events as plain raw text lines to sentinel-raw.log
    One line per event — no formatting, no JSON, no CSV.
    Rotates when file exceeds max_size_mb.
    Thread-safe.
    """

    def __init__(
        self,
        output_dir:   str   = "./logs",
        base_name:    str   = "sentinel-raw",
        max_size_mb:  float = 50.0,
        max_files:    int   = 20,
        compress:     bool  = True,
    ):
        self.output_dir = Path(output_dir)
        self.base_name  = base_name
        self.max_size   = int(max_size_mb * 1024 * 1024)
        self.max_files  = max_files
        self.compress   = compress
        self._lock      = threading.Lock()
        self._fh        = None
        self._current_path: Optional[Path] = None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._open_file()
        logger.info(f"Raw log writer started → {self._current_path}")

    # ── file management ───────────────────────────────────────────────────────

    def _log_path(self) -> Path:
        return self.output_dir / f"{self.base_name}.log"

    def _open_file(self):
        self._current_path = self._log_path()
        self._fh = open(self._current_path, "a", encoding="utf-8")

    def _rotate(self):
        if self._fh:
            self._fh.close()

        ts      = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rotated = self.output_dir / f"{self.base_name}.{ts}.log"
        self._current_path.rename(rotated)

        if self.compress:
            gz_path = rotated.with_suffix(".log.gz")
            with open(rotated, "rb") as fin, gzip.open(gz_path, "wb") as fout:
                fout.write(fin.read())
            rotated.unlink()

        # Prune old archives
        archives = sorted(
            self.output_dir.glob(f"{self.base_name}.*.log*"),
            key=lambda p: p.stat().st_mtime,
        )
        while len(archives) > self.max_files:
            archives.pop(0).unlink(missing_ok=True)

        self._open_file()

    # ── format ────────────────────────────────────────────────────────────────

    def _format(self, event: dict) -> str:
        """
        Build a single raw log line from event dict.
        No JSON — plain key=value pairs.
        """
        # Timestamp
        ts_raw = event.get("timestamp", "")
        try:
            dt  = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            ts  = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            ts  = ts_raw or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        severity  = (event.get("severity",  "info") or "info").upper().ljust(8)
        category  = (event.get("category",  "")     or "").ljust(16)
        action    = (event.get("action",    "")     or "").ljust(20)
        collector = (event.get("collector", "")     or "")

        # Host
        host     = event.get("host") or {}
        hostname = host.get("hostname") or host.get("name") or ""
        host_ip  = host.get("ip") or host.get("ip_address") or ""

        # User
        user_obj = event.get("user") or {}
        username = user_obj.get("name") or user_obj.get("username") or ""

        # Process
        proc     = event.get("process") or {}
        pid      = proc.get("pid") or ""
        pname    = proc.get("name") or proc.get("executable") or ""

        # File
        file_obj = event.get("file") or {}
        fpath    = file_obj.get("path") or ""
        fname    = file_obj.get("name") or ""

        # Network
        net      = event.get("network") or {}
        src_ip   = net.get("src_ip")   or net.get("source_ip")   or ""
        src_port = net.get("src_port") or net.get("source_port") or ""
        dst_ip   = net.get("dst_ip")   or net.get("dest_ip")     or ""
        dst_port = net.get("dst_port") or net.get("dest_port")   or ""
        proto    = net.get("protocol") or ""

        # Tags
        tags     = event.get("tags") or []
        tags_str = "|".join(str(t) for t in tags) if isinstance(tags, list) else str(tags)

        # Notes
        notes    = event.get("notes") or ""

        # ── Build line ────────────────────────────────────────────────────────
        parts = [f"[{ts}]", f"[{severity}]", f"[{category.strip()}]",
                 f"[{action.strip()}]", f"[{collector}]"]

        if hostname: parts.append(f"HOST={hostname}")
        if host_ip:  parts.append(f"IP={host_ip}")
        if username: parts.append(f"USER={username}")
        if pid:      parts.append(f"PID={pid}")
        if pname:    parts.append(f"PROC={pname}")
        if fpath:    parts.append(f"PATH={fpath}")
        if fname and fname != fpath: parts.append(f"FILE={fname}")
        if src_ip:   parts.append(f"SRC={src_ip}:{src_port}" if src_port else f"SRC={src_ip}")
        if dst_ip:   parts.append(f"DST={dst_ip}:{dst_port}" if dst_port else f"DST={dst_ip}")
        if proto:    parts.append(f"PROTO={proto}")
        if tags_str: parts.append(f"TAGS={tags_str}")
        if notes:    parts.append(f"NOTES={notes}")

        return " ".join(parts)

    # ── public API ────────────────────────────────────────────────────────────

    def write(self, event: dict):
        line = self._format(event) + "\n"
        with self._lock:
            try:
                self._fh.write(line)
                self._fh.flush()
                if self._current_path.stat().st_size > self.max_size:
                    self._rotate()
            except Exception as e:
                logger.error(f"Raw log write error: {e}")

    def close(self):
        with self._lock:
            if self._fh:
                self._fh.close()
