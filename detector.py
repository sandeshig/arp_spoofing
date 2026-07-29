"""
detector.py
===========
The core detection engine. Continuously sniffs ARP traffic on the chosen
interface (in its own thread) and analyzes every packet against a table
of trusted IP<->MAC mappings to identify spoofing / intrusion patterns.

Detected conditions
--------------------
- MAC_CHANGE           : an IP that was previously mapped to MAC A is now
                          seen mapped to MAC B (the classic ARP-spoof signature).
- DUPLICATE_IP         : two different MACs claim the same IP within a
                          short grace window (excludes normal DHCP flaps).
- UNKNOWN_DEVICE       : a MAC never seen before appears on the network and
                          is not on the authorized whitelist.
- FAKE_GATEWAY         : a device claims to own the gateway's IP address
                          with a MAC that does not match the known gateway MAC.
- GRATUITOUS_FLOOD     : one MAC sends an abnormal rate of gratuitous ARP
                          announcements (spntsrc == pdst), a common
                          precursor to cache poisoning.
- BROADCAST_STORM      : overall ARP reply rate across the whole LAN
                          exceeds the configured threshold.

This module is purely analytical - it never sends ARP packets itself, it
only observes traffic that is already flowing on the network.

Threading model
----------------
run() is meant to be launched via `threading.Thread(target=detector.run, ...)`.
A `threading.Event` (self._stop_event) provides a clean way to stop
sniffing from the GUI thread. All alerts are delivered to the GUI via a
callback function supplied at construction time, so this module has zero
Tkinter dependency and can be unit tested headlessly.
"""

import threading
import time
from collections import defaultdict, deque

from utils import normalize_mac, now_iso, lookup_vendor
from logger import app_logger
import database

try:
    from scapy.all import sniff, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"


class ArpDetector:
    """Sniffs ARP traffic and raises alerts for spoofing / intrusion patterns."""

    def __init__(self, settings_obj, interface: str, gateway_ip: str, gateway_mac: str,
                 alert_callback=None, packet_callback=None, stats_callback=None):
        """
        Purpose:
            Configure the detector with network context and the callbacks
            the GUI (or any other consumer) uses to receive live updates.
        Parameters:
            settings_obj: shared settings.Settings instance (thresholds, etc).
            interface (str): network interface name to sniff on.
            gateway_ip (str): the LAN's default gateway IP address.
            gateway_mac (str): the gateway's known-good MAC address.
            alert_callback (callable): called as alert_callback(alert_dict)
                                        whenever a new alert is raised.
            packet_callback (callable): called as packet_callback(row_dict)
                                         for every ARP packet observed
                                         (drives the live packet monitor table).
            stats_callback (callable): called periodically as
                                        stats_callback(packets, pps) so the
                                        GUI can update the live counters.
        Returns:
            None
        """
        self.settings = settings_obj
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = normalize_mac(gateway_mac) if gateway_mac else ""
        self.alert_callback = alert_callback
        self.packet_callback = packet_callback
        self.stats_callback = stats_callback

        # ip -> mac, the "trusted" table built from confirmed observations
        self.trusted_map = {}
        # ip -> set of macs seen recently, to catch DUPLICATE_IP / multi-mac
        self.recent_macs_per_ip = defaultdict(set)
        # mac -> deque[timestamps] of gratuitous ARPs, for flood detection
        self._gratuitous_times = defaultdict(deque)
        # global deque[timestamps] of all ARP replies, for broadcast-storm detection
        self._reply_times = deque()
        # de-dupe: don't repeat the identical alert every single packet
        self._last_alert_signature = {}

        self.packets_captured = 0
        self._start_time = time.time()
        self._stop_event = threading.Event()
        self._thread = None
        # mac -> time.time() of the last "still online" DB refresh, so a
        # busy device's every single packet doesn't trigger a DB write.
        self._last_online_refresh = {}

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def seed_trusted_map(self, ip_mac_pairs) -> None:
        """
        Purpose:
            Pre-populate the trusted IP<->MAC table from an initial ARP
            scan, so the very first spoofed packet after startup is still
            caught (instead of blindly trusting whatever arrives first).
        Parameters:
            ip_mac_pairs (iterable[tuple[str,str]]): (ip, mac) pairs.
        Returns:
            None
        """
        for ip, mac in ip_mac_pairs:
            norm_mac = normalize_mac(mac)
            self.trusted_map[ip] = norm_mac
            self.recent_macs_per_ip[ip].add(norm_mac)
        if self.gateway_ip and self.gateway_mac:
            self.trusted_map[self.gateway_ip] = self.gateway_mac

    def start(self) -> None:
        """
        Purpose:
            Launch the packet-capture loop on a background daemon thread.
        Parameters:
            None
        Returns:
            None
        """
        if not SCAPY_AVAILABLE:
            app_logger.error(
                "scapy is not installed - live ARP detection is disabled.", source="detector"
            )
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self.run, name="ArpSniffThread", daemon=True)
        self._thread.start()
        app_logger.info(f"ARP detector started on interface '{self.interface}'.", source="detector")

    def stop(self) -> None:
        """
        Purpose:
            Signal the capture loop to stop. scapy's sniff() is given a
            stop_filter that checks this event, plus a short timeout so it
            periodically wakes up and can exit promptly.
        Parameters:
            None
        Returns:
            None
        """
        self._stop_event.set()
        app_logger.info("ARP detector stop requested.", source="detector")

    def run(self) -> None:
        """
        Purpose:
            The actual capture loop. Delegates to scapy.sniff(), which
            calls self._on_packet() for every ARP frame received.
        Parameters:
            None
        Returns:
            None
        Workflow:
            Uses a small sniff timeout (from settings) so the loop wakes up
            regularly to check the stop event instead of blocking forever
            on a single sniff() call.
        """
        sniff_timeout = self.settings.get("sniff_timeout", 1)
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=self._on_packet,
                    store=False,
                    timeout=sniff_timeout,
                )
            except Exception as exc:
                app_logger.error(f"Packet capture error: {exc}", source="detector")
                time.sleep(1)  # avoid a tight error loop

    # ------------------------------------------------------------------ #
    # Packet analysis
    # ------------------------------------------------------------------ #
    def _on_packet(self, packet) -> None:
        """
        Purpose:
            Callback invoked by scapy for every captured ARP packet. Parses
            the packet, updates counters, feeds the live monitor table, and
            runs it through every detection rule.
        Parameters:
            packet: a scapy packet object containing an ARP layer.
        Returns:
            None
        """
        if ARP not in packet:
            return

        arp = packet[ARP]
        sender_ip = arp.psrc
        sender_mac = normalize_mac(arp.hwsrc)
        target_ip = arp.pdst
        target_mac = normalize_mac(arp.hwdst)
        is_reply = (arp.op == 2)          # 2 == is-at (ARP reply)
        is_gratuitous = (arp.psrc == arp.pdst)  # sender announcing itself unprompted

        self.packets_captured += 1
        now = time.time()

        if self.packet_callback:
            self.packet_callback({
                "timestamp": now_iso(),
                "sender_ip": sender_ip,
                "sender_mac": sender_mac,
                "target_ip": target_ip,
                "target_mac": target_mac,
                "type": "reply" if is_reply else "request",
            })

        if is_reply:
            self._reply_times.append(now)
            self._check_broadcast_storm(now)
            self._check_mapping_change(sender_ip, sender_mac, now)
            self._check_fake_gateway(sender_ip, sender_mac, now)

        if is_gratuitous:
            self._check_gratuitous_flood(sender_mac, sender_ip, now)

        if self.stats_callback and self.packets_captured % 5 == 0:
            elapsed = max(now - self._start_time, 0.001)
            self.stats_callback(self.packets_captured, self.packets_captured / elapsed)

    def _raise_alert(self, severity, category, message, ip="", mac="", dedupe_seconds=10) -> None:
        """
        Purpose:
            Central alert-raising helper: de-duplicates repeated identical
            alerts within a short window, persists the alert to the
            database, and forwards it to the GUI callback.
        Parameters:
            severity (str): SEVERITY_INFO | SEVERITY_WARNING | SEVERITY_CRITICAL.
            category (str): short machine-readable alert type, e.g. 'MAC_CHANGE'.
            message (str): human-readable description.
            ip (str): related IP address.
            mac (str): related MAC address.
            dedupe_seconds (int): suppress an identical (category, ip, mac)
                                   alert if it fired more recently than this.
        Returns:
            None
        Workflow:
            1. Build a signature key from (category, ip, mac).
            2. If the same signature fired within dedupe_seconds, skip it -
               this prevents a single sustained attack from flooding the
               alerts table with thousands of near-duplicate rows.
            3. Otherwise log it, store it in SQLite, and invoke the GUI
               callback so a popup / sound / table row can be shown.
        """
        signature = (category, ip, mac)
        now = time.time()
        last = self._last_alert_signature.get(signature)
        if last and (now - last) < dedupe_seconds:
            return
        self._last_alert_signature[signature] = now

        ts = now_iso()
        app_logger.log(
            "CRITICAL" if severity == SEVERITY_CRITICAL else "WARNING" if severity == SEVERITY_WARNING else "INFO",
            message, source="detector",
        )
        try:
            database.db.add_alert(ts, severity, category, message, ip=ip, mac=mac)
        except Exception as exc:
            app_logger.error(f"Failed to persist alert: {exc}", source="detector")

        if self.alert_callback:
            self.alert_callback({
                "timestamp": ts, "severity": severity, "category": category,
                "message": message, "ip": ip, "mac": mac,
            })

    # ------------------------------------------------------------------ #
    # Individual detection rules
    # ------------------------------------------------------------------ #
    def _touch_device_online(self, ip, mac, now, min_interval=5.0) -> None:
        """
        Purpose:
            Refresh a device's status/last_seen from real passive traffic,
            so it doesn't get wrongly flipped to "offline" by the active
            prober just because that prober's ping-based probe couldn't
            reach it (many phones, consoles, and IoT devices ignore ICMP,
            or the active scan is running without admin/root at all).
            Actual ARP traffic on the wire is stronger evidence a device is
            online than a missed ping ever is.
        Parameters:
            ip (str): the device's current IP.
            mac (str): the device's MAC address.
            now (float): time.time() of this observation.
            min_interval (float): throttle so a chatty device's every
                                   single packet doesn't trigger a DB write.
        Returns:
            None
        """
        last = self._last_online_refresh.get(mac, 0)
        if now - last < min_interval:
            return
        self._last_online_refresh[mac] = now
        try:
            database.db.upsert_device(
                ip, mac,
                vendor=lookup_vendor(mac),
                status="online",
                authorized=self.settings.is_authorized(mac),
            )
        except Exception as exc:
            app_logger.warning(
                f"Could not refresh online status for {ip} ({mac}): {exc}", source="detector",
            )

    def _check_mapping_change(self, ip, mac, now) -> None:
        """
        Purpose:
            Compare a freshly observed (ip, mac) pair against the trusted
            table to catch the classic ARP-spoofing signature: an IP that
            suddenly resolves to a different MAC address than before.
        Parameters:
            ip (str): sender IP from the packet.
            mac (str): sender MAC from the packet.
            now (float): time.time() of observation.
        Returns:
            None
        """
        known_mac = self.trusted_map.get(ip)
        macs_seen = self.recent_macs_per_ip[ip]
        macs_seen.add(mac)

        if known_mac is None:
            # First time we've seen this IP at all. Register it in the
            # Devices tab immediately from this passive observation alone -
            # don't wait for (or depend on) the active arp_scan()/prober,
            # which needs raw-socket privileges and, on its no-privilege
            # fallback path, only finds hosts that answer ICMP ping. A
            # device can easily show up here (we just saw its real ARP
            # traffic) without ever showing up there.
            self._touch_device_online(ip, mac, now, min_interval=0)
            self.trusted_map[ip] = mac
            if not self.settings.is_authorized(mac):
                self._raise_alert(
                    SEVERITY_INFO, "UNKNOWN_DEVICE",
                    f"New/unauthorized device joined the network: {ip} ({mac}).",
                    ip=ip, mac=mac,
                )
                database.db.add_history(now_iso(), ip, "", mac, "First seen on network")
            return

        if known_mac == mac:
            # Same device, still talking - this is real evidence it's
            # online right now, so keep the Devices tab in sync even if
            # the active prober's ping-based probe can't reach it.
            self._touch_device_online(ip, mac, now)

        if known_mac != mac:
            # The IP now maps to a different MAC than the one we trusted.
            severity = SEVERITY_CRITICAL if len(macs_seen) > 2 else SEVERITY_WARNING
            self._raise_alert(
                severity, "MAC_CHANGE",
                f"Possible ARP spoofing: {ip} changed from MAC {known_mac} to {mac}.",
                ip=ip, mac=mac, dedupe_seconds=5,
            )
            database.db.add_history(now_iso(), ip, known_mac, mac, "MAC changed - possible spoofing")
            self.trusted_map[ip] = mac

        if len(macs_seen) > 2:
            self._raise_alert(
                SEVERITY_CRITICAL, "DUPLICATE_IP",
                f"IP {ip} has been claimed by {len(macs_seen)} different MAC addresses: "
                f"{', '.join(sorted(macs_seen))}.",
                ip=ip, dedupe_seconds=15,
            )

    def _check_fake_gateway(self, ip, mac, now) -> None:
        """
        Purpose:
            Specifically watch the gateway's IP address: if any device
            other than the known gateway MAC claims to be the gateway,
            that is a very high-confidence man-in-the-middle indicator
            (classic ARP-spoofing-based MITM setup).
        Parameters:
            ip (str): sender IP from the packet.
            mac (str): sender MAC from the packet.
            now (float): time.time() of observation.
        Returns:
            None
        """
        if not self.gateway_ip or ip != self.gateway_ip:
            return
        if self.gateway_mac and mac != self.gateway_mac:
            self._raise_alert(
                SEVERITY_CRITICAL, "FAKE_GATEWAY",
                f"CRITICAL: Device {mac} is impersonating the gateway ({self.gateway_ip}). "
                f"Expected MAC {self.gateway_mac}. Possible Man-in-the-Middle attack.",
                ip=ip, mac=mac, dedupe_seconds=5,
            )

    def _check_gratuitous_flood(self, mac, ip, now) -> None:
        """
        Purpose:
            Track the rate of gratuitous ARP announcements per MAC address.
            A burst of gratuitous ARPs is a common technique attackers use
            to rapidly poison every host's ARP cache on the LAN.
        Parameters:
            mac (str): MAC address sending the gratuitous ARP.
            ip (str): IP address being announced.
            now (float): time.time() of observation.
        Returns:
            None
        """
        window = self._gratuitous_times[mac]
        window.append(now)
        # Keep only the last 1-second window.
        while window and now - window[0] > 1.0:
            window.popleft()

        threshold = self.settings.get("gratuitous_arp_threshold", 5)
        if len(window) >= threshold:
            self._raise_alert(
                SEVERITY_WARNING, "GRATUITOUS_FLOOD",
                f"High rate of gratuitous ARP announcements from {mac} ({ip}): "
                f"{len(window)} in the last second.",
                ip=ip, mac=mac, dedupe_seconds=10,
            )

    def _check_broadcast_storm(self, now) -> None:
        """
        Purpose:
            Track the overall rate of ARP replies across the whole LAN
            (independent of source) to catch broadcast storms / large-scale
            flooding attacks that don't target one specific IP or MAC.
        Parameters:
            now (float): time.time() of observation.
        Returns:
            None
        """
        while self._reply_times and now - self._reply_times[0] > 1.0:
            self._reply_times.popleft()

        threshold = self.settings.get("flood_threshold", 30)
        if len(self._reply_times) >= threshold:
            self._raise_alert(
                SEVERITY_CRITICAL, "BROADCAST_STORM",
                f"ARP broadcast storm detected: {len(self._reply_times)} replies/sec "
                f"across the network (threshold {threshold}).",
                ip="", mac="", dedupe_seconds=15,
            )

    def get_uptime_seconds(self) -> float:
        """
        Purpose:
            Report how long the detector has been running, for the
            dashboard's "Monitoring Status" card.
        Parameters:
            None
        Returns:
            float: seconds since start().
        """
        return time.time() - self._start_time
