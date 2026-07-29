"""
utils.py
========
Shared helper functions used across the ARP Monitor project.

This module has NO dependency on any other project module, so it can be
safely imported everywhere without circular-import issues.

Contents
--------
- MAC address formatting / validation
- IP address validation helpers
- A small offline OUI (vendor) prefix lookup table + lookup function
- Timestamp helpers
- Simple byte / rate formatting helpers used by the GUI
"""

import re
import ipaddress
from datetime import datetime

# --------------------------------------------------------------------------
# A small, offline table of OUI (Organizationally Unique Identifier) prefixes.
# The first 3 bytes (6 hex chars) of a MAC address identify the manufacturer.
# This is NOT a complete IEEE database (that has 40,000+ entries) - it is a
# reasonably sized offline subset covering common consumer / lab hardware so
# the app can label devices without needing internet access.
# --------------------------------------------------------------------------
OUI_VENDORS = {
    "000C29": "VMware",
    "005056": "VMware",
    "000569": "VMware",
    "080027": "Oracle VirtualBox",
    "00155D": "Microsoft Hyper-V",
    "000D3A": "Microsoft",
    "3C5AB4": "Google",
    "F4F5D8": "Google",
    "DCA632": "Raspberry Pi Foundation",
    "B827EB": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    "001A11": "Google",
    "8863DF": "Apple",
    "A45E60": "Apple",
    "F0DBF8": "Apple",
    "3C0754": "Apple",
    "AC87A3": "Apple",
    "001CB3": "Apple",
    "D0817A": "TP-Link",
    "F4F26D": "TP-Link",
    "50C7BF": "TP-Link",
    "C4E984": "TP-Link",
    "001DD8": "D-Link",
    "1C7EE5": "D-Link",
    "CC5D4E": "D-Link",
    "001E58": "Cisco-Linksys",
    "0022B0": "Cisco-Linksys",
    "C8D719": "Huawei",
    "00E0FC": "Huawei",
    "F83DFF": "Huawei",
    "5CF9DD": "Samsung",
    "8CC8CD": "Samsung",
    "3C5A37": "Samsung",
    "B4E1EB": "Amazon Technologies",
    "68540F": "Amazon Technologies",
    "FCA667": "Amazon Technologies",
    "9C93E4": "Espressif (ESP8266/ESP32)",
    "24B2DE": "Espressif (ESP8266/ESP32)",
    "3C6105": "Espressif (ESP8266/ESP32)",
    "080046": "Sony",
    "001315": "Dell",
    "B499BA": "Dell",
    "D067E5": "Dell",
    "001C23": "Dell",
    "F04DA2": "HP",
    "3CD92B": "HP",
    "9C8E99": "HP",
    "001AA9": "Netgear",
    "204E7F": "Netgear",
    "E091F5": "Netgear",
    "000FB5": "Netgear",
}

UNKNOWN_VENDOR = "Unknown Vendor"


def normalize_mac(mac: str) -> str:
    """
    Purpose:
        Normalize a MAC address string into a consistent, uppercase,
        colon-separated format (e.g. "aa-bb-cc-dd-ee-ff" -> "AA:BB:CC:DD:EE:FF").
    Parameters:
        mac (str): raw MAC address in any common separator style.
    Returns:
        str: normalized MAC address, or the original stripped string if it
             does not look like a MAC address at all.
    Workflow:
        1. Strip whitespace.
        2. Remove separators (':', '-', '.').
        3. Re-insert ':' every 2 hex characters.
        4. Uppercase the result.
    """
    if not mac:
        return ""
    cleaned = re.sub(r"[.:-]", "", mac.strip())
    if len(cleaned) != 12 or not re.match(r"^[0-9A-Fa-f]{12}$", cleaned):
        return mac.strip().upper()
    pairs = [cleaned[i:i + 2] for i in range(0, 12, 2)]
    return ":".join(pairs).upper()


def is_valid_mac(mac: str) -> bool:
    """
    Purpose:
        Check whether a string is a syntactically valid MAC address.
    Parameters:
        mac (str): candidate MAC address string.
    Returns:
        bool: True if it matches the standard 6-octet hex pattern.
    """
    if not mac:
        return False
    pattern = r"^([0-9A-Fa-f]{2}[:\-]){5}([0-9A-Fa-f]{2})$"
    return re.match(pattern, mac.strip()) is not None


def is_valid_ip(ip: str) -> bool:
    """
    Purpose:
        Check whether a string is a syntactically valid IPv4 address.
    Parameters:
        ip (str): candidate IP address string.
    Returns:
        bool: True if ipaddress.ip_address() accepts it as IPv4.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def lookup_vendor(mac: str) -> str:
    """
    Purpose:
        Resolve the manufacturer name for a MAC address using the offline
        OUI_VENDORS table.
    Parameters:
        mac (str): MAC address (any common format).
    Returns:
        str: vendor name if the OUI prefix is known, otherwise
             "Unknown Vendor".
    Workflow:
        1. Normalize the MAC address.
        2. Take the first 3 octets (6 hex chars) as the OUI.
        3. Look the OUI up in the OUI_VENDORS dictionary.
    """
    norm = normalize_mac(mac)
    if not is_valid_mac(norm):
        return UNKNOWN_VENDOR
    oui = norm.replace(":", "")[:6]
    return OUI_VENDORS.get(oui, UNKNOWN_VENDOR)


def now_iso() -> str:
    """
    Purpose:
        Get the current local timestamp as an ISO-8601-like string,
        used consistently for logs, DB rows, and the GUI clock.
    Parameters:
        None.
    Returns:
        str: e.g. "2026-07-25 14:03:11"
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_time_only() -> str:
    """
    Purpose:
        Get just the current local time (HH:MM:SS) for compact display
        in the dashboard clock widget.
    Parameters:
        None.
    Returns:
        str: e.g. "14:03:11"
    """
    return datetime.now().strftime("%H:%M:%S")


def format_rate(count: int, seconds: float) -> str:
    """
    Purpose:
        Convert a raw packet count and a time window into a human
        readable packets-per-second string for the live traffic counter.
    Parameters:
        count (int): number of packets observed.
        seconds (float): time window in seconds (must be > 0 to be meaningful).
    Returns:
        str: e.g. "12.4 pkt/s"
    """
    if seconds <= 0:
        return "0.0 pkt/s"
    return f"{count / seconds:.1f} pkt/s"


def truncate(text: str, length: int = 40) -> str:
    """
    Purpose:
        Truncate long strings (e.g. hostnames) for tidy table display.
    Parameters:
        text (str): input text.
        length (int): maximum length before truncating with an ellipsis.
    Returns:
        str: original text if short enough, otherwise truncated + "...".
    """
    text = text or ""
    return text if len(text) <= length else text[:length - 3] + "..."


def safe_int(value, default=0) -> int:
    """
    Purpose:
        Defensive int conversion so a single malformed field never crashes
        a GUI update or DB insert.
    Parameters:
        value: any value to coerce to int.
        default (int): value to return if conversion fails.
    Returns:
        int: converted integer or the default.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
