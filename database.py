"""
database.py
===========
SQLite persistence layer for the ARP Monitor.

Tables
------
devices     - every device ever seen on the LAN (current known state)
alerts      - every security alert raised by detector.py
history     - append-only IP<->MAC mapping change log (audit trail)
logs        - general application log lines (mirrors logger.py output)
statistics  - periodic counters snapshot (packets captured, alert counts...)

Design notes
------------
- One connection is opened per call via a context manager so this class is
  safe to use from multiple threads (packet capture thread, scanner thread,
  GUI thread) without sharing a single sqlite3.Connection object, which is
  not thread-safe by default.
- `sqlite3.Row` is used as the row_factory so callers can access columns by
  name (row["ip"]) instead of brittle positional indexes.
"""

import sqlite3
import os
import threading
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "arp_monitor.db")

_write_lock = threading.Lock()  # serialize writes; SQLite allows 1 writer at a time


class Database:
    """Thin wrapper around sqlite3 providing schema setup and CRUD helpers."""

    def __init__(self, path: str = DB_PATH):
        """
        Purpose:
            Store the database path and ensure the schema exists.
        Parameters:
            path (str): filesystem path to the .db file.
        Returns:
            None
        """
        self._path = path
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self):
        """
        Purpose:
            Provide a short-lived, auto-committing SQLite connection.
        Parameters:
            None
        Returns:
            Context manager yielding a sqlite3.Connection.
        Workflow:
            1. Open a new connection (cheap in SQLite).
            2. Enable foreign keys and row-name access.
            3. Yield it; commit on clean exit, rollback on exception.
            4. Always close the connection.
        """
        conn = sqlite3.connect(self._path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """
        Purpose:
            Create all required tables if they do not already exist.
        Parameters:
            None
        Returns:
            None
        """
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip              TEXT NOT NULL,
                    mac             TEXT NOT NULL,
                    vendor          TEXT,
                    hostname        TEXT,
                    status          TEXT DEFAULT 'online',
                    authorized      INTEGER DEFAULT 0,
                    first_seen      TEXT,
                    last_seen       TEXT,
                    UNIQUE(mac)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    severity        TEXT NOT NULL,        -- info | warning | critical
                    category        TEXT NOT NULL,        -- e.g. 'MAC_CHANGE', 'FLOOD'
                    ip              TEXT,
                    mac             TEXT,
                    message         TEXT NOT NULL,
                    acknowledged    INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS history (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    ip              TEXT NOT NULL,
                    old_mac         TEXT,
                    new_mac         TEXT,
                    reason          TEXT
                );

                CREATE TABLE IF NOT EXISTS logs (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    level           TEXT NOT NULL,
                    source          TEXT,
                    message         TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS statistics (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp           TEXT NOT NULL,
                    packets_captured    INTEGER DEFAULT 0,
                    devices_online      INTEGER DEFAULT 0,
                    alerts_total        INTEGER DEFAULT 0,
                    alerts_critical     INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_history_ip ON history(ip);
                CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
                """
            )

    # ------------------------------------------------------------------ #
    # Devices
    # ------------------------------------------------------------------ #
    def upsert_device(self, ip, mac, vendor="", hostname="", status="online",
                       authorized=False, seen_at=None) -> None:
        """
        Purpose:
            Insert a new device row or update an existing one (matched by
            MAC address, since MAC is the more stable identifier on a LAN).
        Parameters:
            ip (str): current IP address of the device.
            mac (str): MAC address (used as the unique key).
            vendor (str): resolved vendor name.
            hostname (str): resolved hostname, if any.
            status (str): 'online' or 'offline'.
            authorized (bool): whitelist flag.
            seen_at (str): ISO timestamp string; defaults to "now" if None.
        Returns:
            None
        """
        from utils import now_iso
        ts = seen_at or now_iso()
        with _write_lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT id, first_seen, vendor, hostname FROM devices WHERE mac = ?", (mac,)
            ).fetchone()
            if existing:
                # Don't blank out a vendor/hostname that a previous, more
                # thorough lookup already resolved just because this
                # particular observation (e.g. a quick passive sighting)
                # didn't resolve one itself.
                vendor = vendor or existing["vendor"] or ""
                hostname = hostname or existing["hostname"] or ""
                conn.execute(
                    """UPDATE devices
                       SET ip = ?, vendor = ?, hostname = ?, status = ?, authorized = ?, last_seen = ?
                       WHERE mac = ?""",
                    (ip, vendor, hostname, status, int(authorized), ts, mac),
                )
            else:
                conn.execute(
                    """INSERT INTO devices (ip, mac, vendor, hostname, status, authorized, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ip, mac, vendor, hostname, status, int(authorized), ts, ts),
                )

    def set_device_status(self, mac: str, status: str) -> None:
        """
        Purpose:
            Mark a device online/offline without touching other fields.
        Parameters:
            mac (str): device MAC address.
            status (str): new status string.
        Returns:
            None
        """
        with _write_lock, self._connect() as conn:
            conn.execute("UPDATE devices SET status = ? WHERE mac = ?", (status, mac))

    def set_device_authorized(self, mac: str, authorized: bool) -> None:
        """
        Purpose:
            Flip a device's authorized flag only, without touching its
            status/last_seen/vendor/hostname. Kept separate from
            upsert_device() (which defaults status="online" and always
            bumps last_seen) so that authorizing or de-authorizing a
            currently-offline device doesn't silently mark it "online"
            again just from a whitelist change.
        Parameters:
            mac (str): device MAC address.
            authorized (bool): new authorized flag.
        Returns:
            None
        """
        with _write_lock, self._connect() as conn:
            conn.execute("UPDATE devices SET authorized = ? WHERE mac = ?", (int(authorized), mac))

    def get_all_devices(self):
        """
        Purpose:
            Fetch every known device for the Devices table in the GUI.
        Parameters:
            None
        Returns:
            list[sqlite3.Row]: all rows from the devices table.
        """
        with self._connect() as conn:
            return conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()

    def get_device_by_ip(self, ip: str):
        """
        Purpose:
            Look up the currently trusted MAC for a given IP (used by the
            detector to spot IP-MAC mapping changes).
        Parameters:
            ip (str): IP address to look up.
        Returns:
            sqlite3.Row or None.
        """
        with self._connect() as conn:
            return conn.execute("SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()

    def count_devices(self, status: str = None) -> int:
        """
        Purpose:
            Count devices, optionally filtered by status, for dashboard cards.
        Parameters:
            status (str|None): 'online', 'offline', or None for all.
        Returns:
            int: matching device count.
        """
        with self._connect() as conn:
            if status:
                row = conn.execute("SELECT COUNT(*) c FROM devices WHERE status = ?", (status,)).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) c FROM devices").fetchone()
            return row["c"] if row else 0

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def add_alert(self, timestamp, severity, category, message, ip="", mac="") -> int:
        """
        Purpose:
            Record a new security alert raised by the detection engine.
        Parameters:
            timestamp (str): when the event occurred.
            severity (str): 'info' | 'warning' | 'critical'.
            category (str): short machine-readable alert type.
            message (str): human-readable description.
            ip (str): related IP address, if any.
            mac (str): related MAC address, if any.
        Returns:
            int: the new alert's row id.
        """
        with _write_lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO alerts (timestamp, severity, category, ip, mac, message)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (timestamp, severity, category, ip, mac, message),
            )
            return cur.lastrowid

    def get_recent_alerts(self, limit: int = 200):
        """
        Purpose:
            Fetch the most recent alerts for the Alerts tab.
        Parameters:
            limit (int): maximum rows to return.
        Returns:
            list[sqlite3.Row]
        """
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def count_alerts(self, severity: str = None) -> int:
        """
        Purpose:
            Count alerts, optionally filtered by severity, for dashboard cards.
        Parameters:
            severity (str|None): filter, or None for all alerts.
        Returns:
            int
        """
        with self._connect() as conn:
            if severity:
                row = conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity = ?", (severity,)).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()
            return row["c"] if row else 0

    def alert_category_counts(self):
        """
        Purpose:
            Aggregate alert counts per category, used by graph.py for the
            "Threat Frequency" bar/pie charts.
        Parameters:
            None
        Returns:
            list[sqlite3.Row]: rows with 'category' and 'c' (count) columns.
        """
        with self._connect() as conn:
            return conn.execute(
                "SELECT category, COUNT(*) c FROM alerts GROUP BY category ORDER BY c DESC"
            ).fetchall()

    def alerts_timeline(self, limit: int = 500):
        """
        Purpose:
            Fetch alerts ordered chronologically for the attack timeline chart.
        Parameters:
            limit (int): maximum rows.
        Returns:
            list[sqlite3.Row]
        """
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM alerts ORDER BY id ASC LIMIT ?", (limit,)
            ).fetchall()

    # ------------------------------------------------------------------ #
    # History (IP <-> MAC change audit trail)
    # ------------------------------------------------------------------ #
    def add_history(self, timestamp, ip, old_mac, new_mac, reason) -> None:
        """
        Purpose:
            Record an IP-to-MAC mapping change for the audit trail, used to
            reconstruct "what changed and when" during incident review.
        Parameters:
            timestamp (str): event time.
            ip (str): affected IP address.
            old_mac (str): previously trusted MAC (may be empty for a new IP).
            new_mac (str): newly observed MAC.
            reason (str): short explanation, e.g. "ARP spoof suspected".
        Returns:
            None
        """
        with _write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO history (timestamp, ip, old_mac, new_mac, reason) VALUES (?, ?, ?, ?, ?)",
                (timestamp, ip, old_mac, new_mac, reason),
            )

    def get_history(self, ip: str = None, limit: int = 200):
        """
        Purpose:
            Fetch mapping-change history, optionally filtered to one IP.
        Parameters:
            ip (str|None): filter by IP, or None for all.
            limit (int): maximum rows.
        Returns:
            list[sqlite3.Row]
        """
        with self._connect() as conn:
            if ip:
                return conn.execute(
                    "SELECT * FROM history WHERE ip = ? ORDER BY id DESC LIMIT ?", (ip, limit)
                ).fetchall()
            return conn.execute(
                "SELECT * FROM history ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    # ------------------------------------------------------------------ #
    # Logs
    # ------------------------------------------------------------------ #
    def add_log(self, timestamp, level, source, message) -> None:
        """
        Purpose:
            Mirror an application log line into SQLite so logs are
            queryable (in addition to the flat TXT/CSV/JSON log files
            written by logger.py).
        Parameters:
            timestamp (str): log time.
            level (str): 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL'.
            source (str): originating module/thread name.
            message (str): log message text.
        Returns:
            None
        """
        with _write_lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO logs (timestamp, level, source, message) VALUES (?, ?, ?, ?)",
                (timestamp, level, source, message),
            )

    def get_recent_logs(self, limit: int = 500):
        """
        Purpose:
            Fetch recent log rows for display/export.
        Parameters:
            limit (int): maximum rows.
        Returns:
            list[sqlite3.Row]
        """
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    # ------------------------------------------------------------------ #
    # Statistics
    # ------------------------------------------------------------------ #
    def snapshot_statistics(self, timestamp, packets_captured, devices_online,
                             alerts_total, alerts_critical) -> None:
        """
        Purpose:
            Store a point-in-time snapshot of key counters, used to draw
            trend charts over the monitoring session.
        Parameters:
            timestamp (str): snapshot time.
            packets_captured (int): cumulative packet count.
            devices_online (int): current online device count.
            alerts_total (int): cumulative alert count.
            alerts_critical (int): cumulative critical alert count.
        Returns:
            None
        """
        with _write_lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO statistics
                   (timestamp, packets_captured, devices_online, alerts_total, alerts_critical)
                   VALUES (?, ?, ?, ?, ?)""",
                (timestamp, packets_captured, devices_online, alerts_total, alerts_critical),
            )

    def get_statistics(self, limit: int = 200):
        """
        Purpose:
            Fetch recent statistics snapshots for trend charts.
        Parameters:
            limit (int): maximum rows.
        Returns:
            list[sqlite3.Row]
        """
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM statistics ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()


# A single shared instance used across the whole application.
db = Database()
