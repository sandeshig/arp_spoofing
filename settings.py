"""
settings.py
===========
Persistent application settings, stored as JSON on disk.

The Settings class is a thin wrapper around a dictionary that:
  - loads defaults on first run (creates the file if missing)
  - validates/merges saved values on top of defaults (so upgrading the
    app and adding a new setting never crashes on an old settings file)
  - exposes simple get/set/save methods used by settings.py's GUI tab
    and by every other module that needs a configured value
      (e.g. detector.py reads settings.get("refresh_interval"))
"""

import json
import os
import threading

SETTINGS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "config.json")

DEFAULT_SETTINGS = {
    "refresh_interval": 5,          # seconds between full network re-scans
    "sniff_timeout": 1,             # scapy sniff() batch timeout, seconds
    "alert_sound": True,            # play a sound when a new alert fires
    "desktop_notifications": True,  # show OS-level popup notifications
    "auto_export": False,           # automatically export a report on exit
    "auto_export_format": "csv",    # csv | pdf | txt
    "theme": "dark",                # dark | light
    "network_adapter": "auto",      # "auto" or a specific interface name
    "authorized_devices": [],       # list of {"mac": ..., "ip": ..., "label": ...}
    "gratuitous_arp_threshold": 5,  # gratuitous ARP packets/sec that trigger an alert
    "flood_threshold": 30,          # ARP replies/sec that count as a broadcast storm
    "duplicate_ip_grace_seconds": 2,  # tolerate brief flaps before alerting
    "max_log_lines_in_memory": 2000,  # ring-buffer size for the live monitor table
    "live_probe_interval": 6,       # seconds between background ARP sweeps while monitoring is active
}


class Settings:
    """Loads, merges, and persists application settings as JSON."""

    def __init__(self, path: str = SETTINGS_PATH):
        """
        Purpose:
            Initialize the settings object and load (or create) the
            settings file on disk.
        Parameters:
            path (str): filesystem path to the JSON settings file.
        Returns:
            None
        Workflow:
            1. Store the path and create a re-entrant lock (settings can be
               read from the GUI thread and written from a settings dialog).
            2. Call load() to populate self._data.
        """
        self._path = path
        self._lock = threading.RLock()
        self._data = dict(DEFAULT_SETTINGS)
        self.load()

    def load(self) -> None:
        """
        Purpose:
            Load settings from disk, merging saved values on top of the
            defaults so missing keys are always filled in.
        Parameters:
            None
        Returns:
            None
        Workflow:
            1. If the file doesn't exist, write out the defaults.
            2. Otherwise read the JSON and merge it over DEFAULT_SETTINGS.
            3. On any parse error, fall back to defaults rather than crash.
        """
        with self._lock:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            if not os.path.exists(self._path):
                self._data = dict(DEFAULT_SETTINGS)
                self.save()
                return
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                merged = dict(DEFAULT_SETTINGS)
                merged.update(saved)
                self._data = merged
            except (json.JSONDecodeError, OSError):
                self._data = dict(DEFAULT_SETTINGS)

    def save(self) -> None:
        """
        Purpose:
            Persist the current in-memory settings dictionary to disk.
        Parameters:
            None
        Returns:
            None
        """
        with self._lock:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=4)

    def get(self, key: str, default=None):
        """
        Purpose:
            Read a single setting value.
        Parameters:
            key (str): setting name.
            default: value to return if the key is missing.
        Returns:
            The stored value, or `default`.
        """
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value, persist: bool = True) -> None:
        """
        Purpose:
            Update a single setting value and (optionally) save immediately.
        Parameters:
            key (str): setting name.
            value: new value.
            persist (bool): if True, write the whole settings file to disk
                             right away; if False, caller will batch-save.
        Returns:
            None
        """
        with self._lock:
            self._data[key] = value
            if persist:
                self.save()

    def as_dict(self) -> dict:
        """
        Purpose:
            Get a shallow copy of all current settings (used to populate
            the Settings tab form in the GUI).
        Parameters:
            None
        Returns:
            dict: copy of the internal settings dictionary.
        """
        with self._lock:
            return dict(self._data)

    def add_authorized_device(self, ip: str, mac: str, label: str = "") -> None:
        """
        Purpose:
            Add a device to the authorized device whitelist used by
            detector.py to distinguish "new unknown device" alerts from
            already-trusted devices.
        Parameters:
            ip (str): device IP address.
            mac (str): device MAC address.
            label (str): human friendly name, e.g. "My Laptop".
        Returns:
            None
        """
        with self._lock:
            devices = self._data.get("authorized_devices", [])
            devices = [d for d in devices if d.get("mac") != mac]
            devices.append({"ip": ip, "mac": mac, "label": label})
            self._data["authorized_devices"] = devices
            self.save()

    def remove_authorized_device(self, mac: str) -> None:
        """
        Purpose:
            Remove a device from the authorized whitelist by MAC address.
        Parameters:
            mac (str): MAC address to remove.
        Returns:
            None
        """
        with self._lock:
            devices = self._data.get("authorized_devices", [])
            self._data["authorized_devices"] = [d for d in devices if d.get("mac") != mac]
            self.save()

    def is_authorized(self, mac: str) -> bool:
        """
        Purpose:
            Check whether a MAC address is on the authorized whitelist.
        Parameters:
            mac (str): MAC address to check.
        Returns:
            bool: True if present in authorized_devices.
        """
        with self._lock:
            return any(d.get("mac") == mac for d in self._data.get("authorized_devices", []))


# A single shared instance used across the whole application.
settings = Settings()
