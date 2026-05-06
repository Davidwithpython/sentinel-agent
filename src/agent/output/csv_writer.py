"""
Sentinel Agent - CSV Writer
Writes all raw events to a single flat CSV file.
One row per event — no JSON formatting, human readable, opens in Excel.

Columns:
    timestamp, category, action, outcome, severity, collector,
    hostname, host_ip, host_os,
    user, pid, process_name,
    file_path, file_name,
    src_ip, src_port, dst_ip, dst_port, protocol,
    tags, notes
"""

import csv
import threading
import gzip
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..logger import Logger

logger = Logger.get_logger(__name__)

# All columns in order — fixed so CSV header never changes
CSV_COLUMNS = [
    "timestamp",
    "category",
    "action",
    "outcome",
    "severity",
    "collector",
    # host
    "hostname",
    "host_ip",
    "host_os",
    # user
    "user",
    # process
    "pid",
    "process_name",
    # file
    "file_path",
    "file_name",
    # network
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    # extra
    "tags",
    "notes",
]


def _flatten(event: dict) -> dict:
    """
    Flatten a nested SentinelEvent dict into a single-level dict
    matching CSV_COLUMNS. Missing fields become empty string.
    """
    host    = event.get("host")    or {}
    user    = event.get("user")    or {}
    process = event.get("process") or {}
    file_   = event.get("file")    or {}
    network = event.get("network") or {}

    # tags — join list into pipe-separated string
    tags = event.get("tags") or []
    tags_str = "|".join(str(t) for t in tags) if isinstance(tags, list) else str(tags)

    return {
        "timestamp":    event.get("timestamp", ""),
        "category":     event.get("category",  ""),
        "action":       event.get("action",     ""),
        "outcome":      event.get("outcome",    ""),
        "severity":     event.get("severity",   ""),
        "collector":    event.get("collector",  ""),
        # host
        "hostname":     host.get("hostname", "") or host.get("name", ""),
        "host_ip":      host.get("ip", "")       or host.get("ip_address", ""),
        "host_os":      host.get("os", "")       or host.get("platform", ""),
        # user
        "user":         user.get("name", "")     or user.get("username", ""),
        # process
        "pid":          str(process.get("pid", "")),
        "process_name": process.get("name", "")  or process.get("executable", ""),
        # file
        "file_path":    file_.get("path", ""),
        "file_name":    file_.get("name", ""),
        # network
        "src_ip":       network.get("src_ip", "")   or network.get("source_ip", ""),
        "src_port":     str(network.get("src_port", "") or network.get("source_port", "")),
        "dst_ip":       network.get("dst_ip", "")   or network.get("dest_ip", ""),
        "dst_port":     str(network.get("dst_port", "") or network.get("dest_port", "")),
        "protocol":     network.get("protocol", ""),
        # extra
        "tags":         tags_str,
        "notes":        event.get("notes", ""),
    }


class RotatingCSVWriter:
    """
    Writes events to a rotating CSV file.
    Rotates when file exceeds max_size_mb.
    Keeps last max_files archives (gzip compressed).
    Thread-safe.
    """

    def __init__(
        self,
        output_dir: str  = "./logs",
        base_name: str   = "sentinel-raw",
        max_size_mb: float = 50.0,
        max_files: int   = 20,
        compress: bool   = True,
    ):
        self.output_dir = Path(output_dir)
        self.base_name  = base_name
        self.max_size   = int(max_size_mb * 1024 * 1024)
        self.max_files  = max_files
        self.compress   = compress
        self._lock      = threading.Lock()
        self._fh        = None
        self._writer    = None
        self._current_path: Optional[Path] = None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._open_file()
        logger.info(f"CSV writer started → {self._current_path}")

    def _csv_path(self) -> Path:
        return self.output_dir / f"{self.base_name}.csv"

    def _open_file(self):
        self._current_path = self._csv_path()
        is_new = not self._current_path.exists() or self._current_path.stat().st_size == 0
        self._fh     = open(self._current_path, "a", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(
            self._fh,
            fieldnames = CSV_COLUMNS,
            extrasaction = "ignore",
            lineterminator = "\r\n",
        )
        # Write header only for new/empty files
        if is_new:
            self._writer.writeheader()
            self._fh.flush()

    def _rotate(self):
        if self._fh:
            self._fh.close()

        ts      = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rotated = self.output_dir / f"{self.base_name}.{ts}.csv"
        self._current_path.rename(rotated)

        if self.compress:
            gz_path = rotated.with_suffix(".csv.gz")
            with open(rotated, "rb") as fin, gzip.open(gz_path, "wb") as fout:
                fout.write(fin.read())
            rotated.unlink()

        # Prune old archives
        archives = sorted(
            self.output_dir.glob(f"{self.base_name}.*.csv*"),
            key=lambda p: p.stat().st_mtime,
        )
        while len(archives) > self.max_files:
            archives.pop(0).unlink(missing_ok=True)

        self._open_file()

    def write(self, event: dict):
        """Flatten event and write one CSV row."""
        row = _flatten(event)
        with self._lock:
            try:
                self._writer.writerow(row)
                self._fh.flush()
                if self._current_path.stat().st_size > self.max_size:
                    self._rotate()
            except Exception as e:
                logger.error(f"CSV write error: {e}")

    def close(self):
        with self._lock:
            if self._fh:
                self._fh.close()
