"""
logger.py
=========
Central logging for the ARP Monitor. Every significant event (info,
warning, alert, error) passes through AppLogger.log(), which fans it out
to four sinks simultaneously:

    1. logs/arp_monitor.log   - plain text, human readable (via stdlib logging)
    2. logs/arp_monitor.csv   - one row per event, easy to open in Excel
    3. logs/arp_monitor.json  - JSON Lines (one JSON object per line)
    4. database.db "logs" table - queryable from the GUI

This module is intentionally decoupled from the GUI: it never touches
Tkinter, so it is safe to call from any background thread.
"""

import csv
import json
import logging
import os
import threading
from logging.handlers import RotatingFileHandler

from utils import now_iso
import database

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
TXT_LOG_PATH = os.path.join(LOG_DIR, "arp_monitor.log")
CSV_LOG_PATH = os.path.join(LOG_DIR, "arp_monitor.csv")
JSON_LOG_PATH = os.path.join(LOG_DIR, "arp_monitor.json")

CSV_HEADERS = ["timestamp", "level", "source", "message"]


class AppLogger:
    """Fan-out logger writing to TXT, CSV, JSON, and SQLite simultaneously."""

    def __init__(self):
        """
        Purpose:
            Set up the log directory, the rotating text log handler, and
            the CSV file header (written once).
        Parameters:
            None
        Returns:
            None
        """
        os.makedirs(LOG_DIR, exist_ok=True)
        self._lock = threading.Lock()

        self._text_logger = logging.getLogger("arp_monitor")
        self._text_logger.setLevel(logging.DEBUG)
        if not self._text_logger.handlers:
            handler = RotatingFileHandler(TXT_LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
            formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            handler.setFormatter(formatter)
            self._text_logger.addHandler(handler)

        if not os.path.exists(CSV_LOG_PATH):
            with open(CSV_LOG_PATH, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(CSV_HEADERS)

    def log(self, level: str, message: str, source: str = "app") -> None:
        """
        Purpose:
            Record one event across all four log sinks.
        Parameters:
            level (str): 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL'.
            message (str): human-readable log message.
            source (str): originating module/thread, e.g. 'detector'.
        Returns:
            None
        Workflow:
            1. Timestamp the event.
            2. Write to the rotating text log via stdlib logging.
            3. Append a row to the CSV log.
            4. Append a line to the JSON-lines log.
            5. Insert a row into the SQLite `logs` table.
            Each sink is wrapped so a failure in one (e.g. disk full)
            doesn't prevent the others from recording the event.
        """
        ts = now_iso()
        level = level.upper()

        with self._lock:
            try:
                log_fn = getattr(self._text_logger, level.lower(), self._text_logger.info)
                log_fn(f"[{source}] {message}")
            except Exception:
                pass

            try:
                with open(CSV_LOG_PATH, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow([ts, level, source, message])
            except Exception:
                pass

            try:
                with open(JSON_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "timestamp": ts, "level": level, "source": source, "message": message
                    }) + "\n")
            except Exception:
                pass

            try:
                database.db.add_log(ts, level, source, message)
            except Exception:
                pass

    # Convenience wrappers -------------------------------------------------
    def debug(self, message: str, source: str = "app") -> None:
        """Purpose: log a DEBUG-level event. Parameters: message, source. Returns: None."""
        self.log("DEBUG", message, source)

    def info(self, message: str, source: str = "app") -> None:
        """Purpose: log an INFO-level event. Parameters: message, source. Returns: None."""
        self.log("INFO", message, source)

    def warning(self, message: str, source: str = "app") -> None:
        """Purpose: log a WARNING-level event. Parameters: message, source. Returns: None."""
        self.log("WARNING", message, source)

    def error(self, message: str, source: str = "app") -> None:
        """Purpose: log an ERROR-level event. Parameters: message, source. Returns: None."""
        self.log("ERROR", message, source)

    def critical(self, message: str, source: str = "app") -> None:
        """Purpose: log a CRITICAL-level event. Parameters: message, source. Returns: None."""
        self.log("CRITICAL", message, source)


# A single shared instance used across the whole application.
app_logger = AppLogger()
