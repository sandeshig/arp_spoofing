"""
main.py
=======
Application entry point and GUI. Builds a dark, cybersecurity-themed
desktop dashboard (ttkbootstrap on top of Tkinter) with a sidebar and the
following tabs:

    Dashboard | Devices | Live Monitor | Alerts | Reports | Graphs | Settings | About

Threading model
----------------
All network I/O (ARP scanning, packet sniffing) happens on background
daemon threads (scanner.py / detector.py). Those threads never touch
Tkinter widgets directly - Tkinter is not thread-safe. Instead they push
events onto a thread-safe queue.Queue, and the GUI drains that queue on a
regular `root.after()` timer tick running on the main thread. This is the
standard, safe pattern for combining Tkinter with background threads.

Run:
    python main.py
"""

import os
import platform
import queue
import subprocess
import threading
import time
from datetime import datetime

try:
    import ttkbootstrap as tb
    from ttkbootstrap.constants import *
    TTKBOOTSTRAP_AVAILABLE = True
except ImportError:
    # Fall back to plain tkinter/ttk styling if ttkbootstrap isn't installed.
    import tkinter as tk
    from tkinter import ttk
    TTKBOOTSTRAP_AVAILABLE = False

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from settings import settings
from logger import app_logger
import database
import utils
import scanner
import detector
import notifier
import graph
import exporter
import demo_simulator

APP_TITLE = "ARP Monitor - Real-Time ARP Spoofing Detection & LAN Intrusion Monitoring"
REFRESH_MS = 500  # GUI queue-drain / clock tick interval

# Maps the user-facing Settings choice to an actual ttkbootstrap theme name.
# "flatly" and "cyborg" are both built-in ttkbootstrap themes.
THEME_MAP = {"dark": "cyborg", "light": "flatly"}


class ArpMonitorApp:
    """The main application window and all its tabs/widgets."""

    def __init__(self):
        """
        Purpose:
            Build the root window, sidebar navigation, all tab frames, and
            start the periodic GUI update timer. Does NOT start packet
            capture automatically - the user starts monitoring explicitly
            from the Dashboard, since it requires elevated OS privileges.
        Parameters:
            None
        Returns:
            None
        """
        initial_theme = THEME_MAP.get(settings.get("theme", "dark"), "cyborg")
        self.root = tb.Window(themename=initial_theme) if TTKBOOTSTRAP_AVAILABLE else tk.Tk()
        self.root.title(APP_TITLE)
        self.root.geometry("1280x800")
        self.root.minsize(1024, 680)

        self.event_queue = queue.Queue()
        self.scanner = scanner.NetworkScanner(settings)
        self.detector = None  # created when monitoring starts (needs interface/gateway info)
        self.network_info = {}
        self.monitoring = False
        self.packets_seen = 0
        self.pps_current = 0.0
        self._live_rows_shown = 0
        self._prober_stop_event = None   # set while the active-probe thread is running
        self._offline_miss_counts = {}   # mac -> consecutive missed active-probe sweeps
        self._last_graph_refresh = 0.0   # time.time() of the last Graphs tab rebuild

        self._build_layout()
        self._discover_network(initial=True)
        self._refresh_devices_table()
        self._refresh_alerts_table()
        self.root.after(REFRESH_MS, self._tick)

    # ------------------------------------------------------------------ #
    # Layout construction
    # ------------------------------------------------------------------ #
    def _build_layout(self):
        """
        Purpose:
            Construct the sidebar + content-area shell and instantiate
            every tab frame.
        Parameters:
            None
        Returns:
            None
        """
        container = ttk.Frame(self.root)
        container.pack(fill="both", expand=True)

        sidebar = ttk.Frame(container, width=200)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        title_lbl = ttk.Label(sidebar, text="🛡 ARP MONITOR", font=("Segoe UI", 14, "bold"))
        title_lbl.pack(pady=(20, 10), padx=10)

        self.content = ttk.Frame(container)
        self.content.pack(side="right", fill="both", expand=True)

        self.tabs = {}
        self.tab_buttons = {}
        tab_names = ["Dashboard", "Devices", "Live Monitor", "Alerts", "Reports", "Graphs", "Settings", "About"]
        builders = [
            self._build_dashboard_tab, self._build_devices_tab, self._build_live_monitor_tab,
            self._build_alerts_tab, self._build_reports_tab, self._build_graphs_tab,
            self._build_settings_tab, self._build_about_tab,
        ]

        for name, builder in zip(tab_names, builders):
            frame = ttk.Frame(self.content)
            builder(frame)
            self.tabs[name] = frame

            btn = ttk.Button(sidebar, text=name, command=lambda n=name: self._show_tab(n))
            btn.pack(fill="x", padx=10, pady=3)
            self.tab_buttons[name] = btn

        self.status_bar = ttk.Label(self.root, text="Ready.", anchor="w", relief="sunken")
        self.status_bar.pack(side="bottom", fill="x")

        self._show_tab("Dashboard")

    def _show_tab(self, name: str):
        """
        Purpose:
            Switch the visible content-area tab.
        Parameters:
            name (str): tab name key from self.tabs.
        Returns:
            None
        """
        for frame in self.tabs.values():
            frame.pack_forget()
        self.tabs[name].pack(fill="both", expand=True, padx=16, pady=16)

        if name == "Graphs" and hasattr(self, "_last_graph_refresh"):
            self._maybe_auto_refresh_graphs()
        elif name == "Reports" and hasattr(self, "reports_tree"):
            self._refresh_reports_list()

    # ------------------------------------------------------------------ #
    # Dashboard tab
    # ------------------------------------------------------------------ #
    def _build_dashboard_tab(self, frame):
        """
        Purpose:
            Build the Dashboard tab: status cards + start/stop controls.
        Parameters:
            frame (ttk.Frame): the parent frame to populate.
        Returns:
            None
        """
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text="Dashboard", font=("Segoe UI", 18, "bold")).pack(side="left")

        self.btn_toggle_monitor = ttk.Button(header, text="▶ Start Monitoring", command=self._toggle_monitoring)
        self.btn_toggle_monitor.pack(side="right")
        ttk.Button(header, text="⟳ Rescan Network", command=lambda: self._discover_network(initial=False)).pack(
            side="right", padx=(0, 8)
        )
        ttk.Button(header, text="🎬 Run Demo Scenario", command=self._run_demo_scenario).pack(
            side="right", padx=(0, 8)
        )

        ttk.Label(
            frame,
            text="Start Monitoring passively sniffs real ARP traffic AND periodically re-sweeps the "
                 "LAN in the background, so Live Monitor/Graphs stay populated with genuine packets "
                 "even on a quiet network, instead of only reacting to whatever traffic happens to "
                 "pass by. Demo Scenario is separate: it feeds synthetic ARP packets (built in memory, "
                 "nothing sent on the network) through the same real detection engine, so every alert "
                 "channel reacts exactly as it would to a genuine attack - useful for presentations "
                 "without needing a second attacking machine.",
            wraplength=1100, foreground="#888888", font=("Segoe UI", 8),
        ).pack(fill="x", pady=(0, 10))

        cards_frame = ttk.Frame(frame)
        cards_frame.pack(fill="x")
        self.dashboard_vars = {}
        card_fields = [
            "Monitoring Status", "System Time", "Current Network Adapter", "Host IP",
            "Host MAC Address", "Gateway IP", "Gateway MAC", "Connected Devices",
            "Alerts Raised", "Packets Captured", "Live Traffic",
        ]
        for i, field in enumerate(card_fields):
            card = ttk.Labelframe(cards_frame, text=field)
            card.grid(row=i // 4, column=i % 4, padx=6, pady=6, sticky="nsew")
            cards_frame.grid_columnconfigure(i % 4, weight=1)
            var = tk.StringVar(value="-")
            ttk.Label(card, textvariable=var, font=("Consolas", 12, "bold")).pack(padx=10, pady=10)
            self.dashboard_vars[field] = var

        self.blink_label = ttk.Label(frame, text="", font=("Segoe UI", 12, "bold"))
        self.blink_label.pack(pady=6)

        recent_frame = ttk.Labelframe(frame, text="Most Recent Alerts")
        recent_frame.pack(fill="both", expand=True, pady=(10, 0))
        cols = ("time", "severity", "category", "message")
        self.recent_alerts_tree = ttk.Treeview(recent_frame, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (90, 80, 130, 500)):
            self.recent_alerts_tree.heading(c, text=c.title())
            self.recent_alerts_tree.column(c, width=w, anchor="w")
        self.recent_alerts_tree.pack(fill="both", expand=True)

    def _toggle_monitoring(self):
        """
        Purpose:
            Start or stop the live ARP detector when the dashboard button
            is clicked.
        Parameters:
            None
        Returns:
            None
        """
        if self.monitoring:
            self._stop_monitoring()
        else:
            self._start_monitoring()

    def _start_monitoring(self):
        """
        Purpose:
            Instantiate and start detector.ArpDetector on the currently
            discovered interface/gateway, wired up to push events onto the
            thread-safe queue for the GUI to consume.
        Parameters:
            None
        Returns:
            None
        """
        if not detector.SCAPY_AVAILABLE:
            messagebox.showerror(
                "Scapy Not Available",
                "The 'scapy' library is required for live packet capture.\n\n"
                "Install it with: pip install scapy\n"
                "and run this application with administrator/root privileges.",
            )
            return

        iface = self.network_info.get("Current Network Adapter", "")
        gateway_ip = self.network_info.get("Gateway IP", "")
        gateway_mac = self.network_info.get("Gateway MAC", "")

        self.detector = detector.ArpDetector(
            settings_obj=settings, interface=iface, gateway_ip=gateway_ip, gateway_mac=gateway_mac,
            alert_callback=lambda a: self.event_queue.put(("alert", a)),
            packet_callback=lambda p: self.event_queue.put(("packet", p)),
            stats_callback=lambda count, pps: self.event_queue.put(("stats", (count, pps))),
        )

        try:
            devices = database.db.get_all_devices()
            self.detector.seed_trusted_map([(d["ip"], d["mac"]) for d in devices])
        except Exception as exc:
            app_logger.warning(f"Could not seed trusted map: {exc}", source="main")

        self.detector.start()
        self._start_active_prober()
        self.monitoring = True
        self.btn_toggle_monitor.config(text="■ Stop Monitoring")
        self.dashboard_vars["Monitoring Status"].set("ACTIVE")
        self._set_status(f"Monitoring started on {iface}.")

    def _stop_monitoring(self):
        """
        Purpose:
            Stop the running detector and the active-probe thread cleanly.
        Parameters:
            None
        Returns:
            None
        """
        if self.detector:
            self.detector.stop()
        self._stop_active_prober()
        self.monitoring = False
        self.btn_toggle_monitor.config(text="▶ Start Monitoring")
        self.dashboard_vars["Monitoring Status"].set("STOPPED")
        self._set_status("Monitoring stopped.")

        if settings.get("auto_export", False):
            self._export_report(settings.get("auto_export_format", "csv"), silent=True)

    def _start_active_prober(self):
        """
        Purpose:
            Launch a background thread that periodically re-sweeps the
            LAN (reusing scanner.arp_scan(), the same mechanism as the
            Devices tab's "Scan Now") while monitoring is active. The
            broadcast ARP requests this sends prompt real reply traffic
            from real devices, which the detector's sniff thread then
            picks up and analyzes exactly like organic traffic - so the
            Live Monitor table, packet counters, and Graphs keep filling
            with genuine data instead of sitting empty on a quiet network
            (this is standard active+passive ARP monitoring, not spoofing
            or synthetic data - it's the same broadcast "who-has" sweep
            the Devices tab already does).
        Parameters:
            None
        Returns:
            None
        """
        stop_event = threading.Event()
        self._prober_stop_event = stop_event
        self._offline_miss_counts = {}
        interval = max(2, settings.get("live_probe_interval", 6))

        def loop():
            # Bound to this specific stop_event instance (not re-read from
            # self) so a quick Stop->Start cycle - which replaces
            # self._prober_stop_event with a fresh Event - can't leave this
            # thread mistakenly watching the new event and running forever.
            while not stop_event.is_set():
                cidr = self.network_info.get("_cidr", "")
                if cidr:
                    try:
                        found = self.scanner.arp_scan(cidr, timeout=2)
                        seen_macs = set()
                        for d in found:
                            seen_macs.add(d["mac"])
                            database.db.upsert_device(
                                d["ip"], d["mac"], vendor=d["vendor"], hostname=d["hostname"],
                                status="online", authorized=settings.is_authorized(d["mac"]),
                            )
                            self._offline_miss_counts[d["mac"]] = 0

                        # A device that was online but missed twice in a row
                        # (tolerant of one dropped probe) gets marked offline
                        # - unless something (this active probe OR the
                        # passive detector, which sees real traffic from
                        # devices that simply don't answer ICMP/ARP probes,
                        # e.g. many phones, consoles, and IoT gear) has
                        # touched it more recently than this probe cycle.
                        # Otherwise a game console mid-match would flicker
                        # "offline" just because it ignored our own probe.
                        grace = max(interval * 2, 15)
                        for existing in database.db.get_all_devices():
                            mac = existing["mac"]
                            if mac in seen_macs or existing["status"] != "online":
                                continue
                            try:
                                last_seen_dt = datetime.strptime(existing["last_seen"], "%Y-%m-%d %H:%M:%S")
                                if (datetime.now() - last_seen_dt).total_seconds() < grace:
                                    self._offline_miss_counts[mac] = 0
                                    continue
                            except (ValueError, TypeError):
                                pass
                            misses = self._offline_miss_counts.get(mac, 0) + 1
                            self._offline_miss_counts[mac] = misses
                            if misses >= 2:
                                database.db.set_device_status(mac, "offline")

                        self.event_queue.put(("scan_done", (len(found), self.scanner.last_scan_method)))
                    except Exception as exc:
                        app_logger.warning(f"Active probe sweep failed: {exc}", source="main")
                stop_event.wait(interval)

        threading.Thread(target=loop, daemon=True, name="ActiveProberThread").start()

    def _stop_active_prober(self):
        """
        Purpose:
            Signal the active-probe thread to stop.
        Parameters:
            None
        Returns:
            None
        """
        if self._prober_stop_event:
            self._prober_stop_event.set()
            self._prober_stop_event = None

    def _run_demo_scenario(self):
        """
        Purpose:
            Run a scripted, safe demonstration of the detection engine for
            presentations/viva demos: synthetic ARP packets are built
            entirely in memory (scapy Ether()/ARP() objects) and fed
            directly into the detector's real analysis code - nothing is
            ever sent on the network, no other device is touched, and no
            raw-socket privileges are required. Every alert channel
            (popup, sound, Alerts tab, Live Monitor tab, Dashboard
            counters, Graphs) reacts exactly as it would to a real attack.
        Parameters:
            None
        Returns:
            None
        Workflow:
            1. If a detector doesn't already exist (monitoring not
               started), build one wired to the same event queue as live
               monitoring uses, but do NOT call .start() - so no sniff
               thread is spawned and no privileges are needed.
            2. Launch demo_simulator.run_demo_scenario() on a background
               thread so the scripted delays between events don't freeze
               the GUI.
        """
        if not detector.SCAPY_AVAILABLE:
            messagebox.showerror(
                "Scapy Not Available",
                "The 'scapy' library is required even for the demo (it's used to build the "
                "in-memory packet objects, though nothing is sent on the network).\n\n"
                "Install it with: pip install scapy",
            )
            return

        if not self.detector:
            iface = self.network_info.get("Current Network Adapter", "")
            gateway_ip = self.network_info.get("Gateway IP", "")
            gateway_mac = self.network_info.get("Gateway MAC", "")
            self.detector = detector.ArpDetector(
                settings_obj=settings, interface=iface, gateway_ip=gateway_ip, gateway_mac=gateway_mac,
                alert_callback=lambda a: self.event_queue.put(("alert", a)),
                packet_callback=lambda p: self.event_queue.put(("packet", p)),
                stats_callback=lambda count, pps: self.event_queue.put(("stats", (count, pps))),
            )

        self._set_status("Running demo scenario - synthetic packets only, nothing sent on the network.")
        threading.Thread(
            target=demo_simulator.run_demo_scenario, args=(self.detector,), kwargs={"delay": 1.0}, daemon=True,
        ).start()

    # ------------------------------------------------------------------ #
    # Devices tab
    # ------------------------------------------------------------------ #
    def _build_devices_tab(self, frame):
        """
        Purpose:
            Build the Devices tab: a table of every known device plus a
            manual "Scan Now" trigger and an "Authorize" action.
        Parameters:
            frame (ttk.Frame): parent frame.
        Returns:
            None
        """
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text="Devices", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Button(header, text="⟳ Scan Now", command=self._manual_scan).pack(side="right")
        ttk.Button(header, text="✖ Remove Authorization", command=self._deauthorize_selected_device).pack(
            side="right", padx=(0, 8)
        )
        ttk.Button(header, text="✔ Authorize Selected", command=self._authorize_selected_device).pack(
            side="right", padx=(0, 8)
        )

        ttk.Label(
            frame,
            text="Click anywhere on a device's row to check it (click again to uncheck) - "
                 "check as many as you want, then click \"Authorize Selected\" or "
                 "\"Remove Authorization\".",
            foreground="#888",
        ).pack(fill="x", pady=(0, 6))

        # Rows a user has explicitly checked via the Select column, keyed by
        # MAC (persists across table refreshes until authorized or unchecked).
        self._checked_devices = set()

        cols = ("select", "ip", "mac", "hostname", "vendor", "status", "last_seen", "authorized")
        self.devices_tree = ttk.Treeview(frame, columns=cols, show="headings")
        widths = (70, 130, 160, 150, 170, 90, 160, 90)
        headings = {"select": "Select", "hostname": "Device Name"}
        for c, w in zip(cols, widths):
            self.devices_tree.heading(c, text=headings.get(c, c.replace("_", " ").title()))
            anchor = "center" if c == "select" else "w"
            self.devices_tree.column(c, width=w, anchor=anchor, stretch=(c != "select"))
        self.devices_tree.pack(fill="both", expand=True)
        self.devices_tree.bind("<Button-1>", self._on_devices_tree_click)

    def _manual_scan(self):
        """
        Purpose:
            Trigger a one-off ARP sweep on a background thread (so the GUI
            doesn't freeze during the scan) and refresh the devices table
            when it completes.
        Parameters:
            None
        Returns:
            None
        """
        self._set_status("Scanning network...")

        def worker():
            try:
                cidr = self.network_info.get("_cidr", "")
                found = self.scanner.arp_scan(cidr, timeout=3)
                for d in found:
                    database.db.upsert_device(
                        d["ip"], d["mac"], vendor=d["vendor"], hostname=d["hostname"],
                        status="online", authorized=settings.is_authorized(d["mac"]),
                    )
                self.event_queue.put(("scan_done", (len(found), self.scanner.last_scan_method)))
            except Exception as exc:
                self.event_queue.put(("scan_error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_devices_tree_click(self, event):
        """
        Purpose:
            Toggle a device's checkbox when a user clicks its row, so
            multiple devices can be picked for "Authorize Selected" with a
            single click each - anywhere on the row, not just the narrow
            "Select" cell (easy to miss, especially since it has no way to
            show a hover/focus cue of its own).
        Parameters:
            event: the Tkinter click event.
        Returns:
            None
        """
        if self.devices_tree.identify_region(event.x, event.y) != "cell":
            return
        row = self.devices_tree.identify_row(event.y)
        if not row:
            return
        mac = self.devices_tree.set(row, "mac")
        if mac in self._checked_devices:
            self._checked_devices.discard(mac)
            self.devices_tree.set(row, "select", "☐")
        else:
            self._checked_devices.add(mac)
            self.devices_tree.set(row, "select", "☑")

    def _authorize_selected_device(self):
        """
        Purpose:
            Add every checked (or, if none are checked, the currently
            row-selected) device in the Devices tab table to the authorized
            whitelist so future detector runs won't flag it as unknown.
        Parameters:
            None
        Returns:
            None
        """
        targets = []  # list of (ip, mac)
        if self._checked_devices:
            for row in self.devices_tree.get_children():
                mac = self.devices_tree.set(row, "mac")
                if mac in self._checked_devices:
                    targets.append((self.devices_tree.set(row, "ip"), mac))
        else:
            selection = self.devices_tree.selection()
            if not selection:
                messagebox.showinfo(
                    "No Selection",
                    "Click a device's row first to check it.",
                )
                return
            targets = [
                (self.devices_tree.set(row, "ip"), self.devices_tree.set(row, "mac"))
                for row in selection
            ]

        for ip, mac in targets:
            settings.add_authorized_device(ip, mac, label="")
            database.db.set_device_authorized(mac, True)

        self._checked_devices.clear()
        self._refresh_devices_table()
        if hasattr(self, "auth_list"):
            self._refresh_authorized_list()
        if len(targets) == 1:
            self._set_status(f"Device {targets[0][1]} authorized.")
        else:
            self._set_status(f"Authorized {len(targets)} device(s).")

    def _deauthorize_selected_device(self):
        """
        Purpose:
            Remove every checked (or, if none are checked, the currently
            row-selected) device in the Devices tab table from the
            authorized whitelist - the opposite of "Authorize Selected".
            A device removed here will be flagged as an unauthorized/
            unknown device again the next time the detector sees it.
        Parameters:
            None
        Returns:
            None
        """
        targets = []  # list of (ip, mac)
        if self._checked_devices:
            for row in self.devices_tree.get_children():
                mac = self.devices_tree.set(row, "mac")
                if mac in self._checked_devices:
                    targets.append((self.devices_tree.set(row, "ip"), mac))
        else:
            selection = self.devices_tree.selection()
            if not selection:
                messagebox.showinfo(
                    "No Selection",
                    "Click a device's row first to check it.",
                )
                return
            targets = [
                (self.devices_tree.set(row, "ip"), self.devices_tree.set(row, "mac"))
                for row in selection
            ]

        for ip, mac in targets:
            settings.remove_authorized_device(mac)
            database.db.set_device_authorized(mac, False)

        self._checked_devices.clear()
        self._refresh_devices_table()
        if hasattr(self, "auth_list"):
            self._refresh_authorized_list()
        if len(targets) == 1:
            self._set_status(f"Removed authorization for {targets[0][1]}.")
        else:
            self._set_status(f"Removed authorization for {len(targets)} device(s).")

    def _refresh_devices_table(self):
        """
        Purpose:
            Reload the Devices tab table from the database.
        Parameters:
            None
        Returns:
            None
        """
        self.devices_tree.delete(*self.devices_tree.get_children())
        for d in database.db.get_all_devices():
            checked = "☑" if d["mac"] in self._checked_devices else "☐"
            self.devices_tree.insert("", "end", values=(
                checked, d["ip"], d["mac"], d["hostname"] or "-", d["vendor"] or "Unknown",
                d["status"], d["last_seen"], "Yes" if d["authorized"] else "No",
            ))
        self.dashboard_vars["Connected Devices"].set(str(database.db.count_devices(status="online")))

    # ------------------------------------------------------------------ #
    # Live Monitor tab
    # ------------------------------------------------------------------ #
    def _build_live_monitor_tab(self, frame):
        """
        Purpose:
            Build the Live Monitor tab: a scrolling table of raw ARP
            packets as they are captured.
        Parameters:
            frame (ttk.Frame): parent frame.
        Returns:
            None
        """
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text="Live Packet Monitor", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Button(header, text="Clear", command=self._clear_live_monitor).pack(side="right")

        cols = ("time", "sender_ip", "sender_mac", "target_ip", "target_mac", "type")
        self.live_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c, w in zip(cols, (90, 120, 140, 120, 140, 80)):
            self.live_tree.heading(c, text=c.replace("_", " ").title())
            self.live_tree.column(c, width=w, anchor="w")
        self.live_tree.pack(fill="both", expand=True)

    def _clear_live_monitor(self):
        """
        Purpose:
            Clear the live packet monitor table (does not affect stored
            logs/database rows, only the on-screen view).
        Parameters:
            None
        Returns:
            None
        """
        self.live_tree.delete(*self.live_tree.get_children())
        self._live_rows_shown = 0

    def _append_live_packet(self, packet_row: dict):
        """
        Purpose:
            Add one packet row to the live monitor table, keeping the
            table capped to max_log_lines_in_memory rows so a long
            monitoring session doesn't slowly bloat GUI memory.
        Parameters:
            packet_row (dict): fields as produced by detector's packet_callback.
        Returns:
            None
        Workflow:
            New rows are inserted at the top (index 0) so the most recent
            packet is always the first thing visible, oldest at the
            bottom - the reverse of a normal append-only log. Trimming
            therefore removes from the bottom (the oldest row), not the
            top, once the row cap is exceeded.
        """
        self.live_tree.insert("", 0, values=(
            packet_row["timestamp"][11:19], packet_row["sender_ip"], packet_row["sender_mac"],
            packet_row["target_ip"], packet_row["target_mac"], packet_row["type"],
        ))
        self._live_rows_shown += 1
        max_rows = settings.get("max_log_lines_in_memory", 2000)
        if self._live_rows_shown > max_rows:
            children = self.live_tree.get_children()
            if children:
                self.live_tree.delete(children[-1])
                self._live_rows_shown -= 1

    # ------------------------------------------------------------------ #
    # Alerts tab
    # ------------------------------------------------------------------ #
    def _build_alerts_tab(self, frame):
        """
        Purpose:
            Build the Alerts tab: a filterable table of every alert raised
            by the detection engine, with severity color tags.
        Parameters:
            frame (ttk.Frame): parent frame.
        Returns:
            None
        """
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text="Alerts", font=("Segoe UI", 18, "bold")).pack(side="left")

        self.alert_filter_var = tk.StringVar(value="all")
        for label, value in [("All", "all"), ("Critical", "critical"), ("Warning", "warning"), ("Info", "info")]:
            ttk.Radiobutton(
                header, text=label, value=value, variable=self.alert_filter_var,
                command=self._refresh_alerts_table,
            ).pack(side="right", padx=4)

        cols = ("time", "severity", "category", "ip", "mac", "message")
        self.alerts_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c, w in zip(cols, (150, 80, 140, 110, 140, 420)):
            self.alerts_tree.heading(c, text=c.title())
            self.alerts_tree.column(c, width=w, anchor="w")
        self.alerts_tree.tag_configure("critical", foreground="#e74c3c")
        self.alerts_tree.tag_configure("warning", foreground="#f1c40f")
        self.alerts_tree.tag_configure("info", foreground="#2ecc71")
        self.alerts_tree.pack(fill="both", expand=True)

    def _refresh_alerts_table(self):
        """
        Purpose:
            Reload the Alerts tab table from the database, applying the
            currently selected severity filter.
        Parameters:
            None
        Returns:
            None
        """
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        severity_filter = self.alert_filter_var.get() if hasattr(self, "alert_filter_var") else "all"
        for a in database.db.get_recent_alerts(limit=500):
            if severity_filter != "all" and a["severity"] != severity_filter:
                continue
            self.alerts_tree.insert("", "end", values=(
                a["timestamp"], a["severity"].upper(), a["category"], a["ip"] or "-", a["mac"] or "-", a["message"],
            ), tags=(a["severity"],))

        self.dashboard_vars["Alerts Raised"].set(str(database.db.count_alerts()))

    # ------------------------------------------------------------------ #
    # Reports tab
    # ------------------------------------------------------------------ #
    def _build_reports_tab(self, frame):
        """
        Purpose:
            Build the Reports tab: export buttons for PDF/CSV/TXT reports.
        Parameters:
            frame (ttk.Frame): parent frame.
        Returns:
            None
        """
        ttk.Label(frame, text="Reports", font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(0, 12))
        ttk.Label(
            frame,
            text="Generate a security report covering the network summary, device summary,\n"
                 "detected threats, ARP statistics, and the attack timeline.",
        ).pack(anchor="w", pady=(0, 16))

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(anchor="w")
        ttk.Button(btn_frame, text="📄 Export PDF Report", command=lambda: self._export_report("pdf")).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(btn_frame, text="📊 Export CSV", command=lambda: self._export_report("csv")).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(btn_frame, text="📝 Export TXT", command=lambda: self._export_report("txt")).pack(side="left")

        # --- Generated Reports: browse and open past exports -------------- #
        list_header = ttk.Frame(frame)
        list_header.pack(fill="x", pady=(20, 6))
        ttk.Label(list_header, text="Generated Reports", font=("Segoe UI", 12, "bold")).pack(side="left")
        ttk.Button(list_header, text="📂 Open Selected", command=self._open_selected_report).pack(
            side="right", padx=(8, 0)
        )
        ttk.Button(list_header, text="🗂 Open Reports Folder", command=self._open_reports_folder).pack(
            side="right", padx=(8, 0)
        )
        ttk.Button(list_header, text="⟳ Refresh List", command=self._refresh_reports_list).pack(side="right")

        cols = ("file", "format", "size", "generated")
        self.reports_tree = ttk.Treeview(frame, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (320, 70, 90, 160)):
            self.reports_tree.heading(c, text=c.title())
            self.reports_tree.column(c, width=w, anchor="w")
        self.reports_tree.pack(fill="both", expand=False)
        self.reports_tree.bind("<Double-1>", lambda _e: self._open_selected_report())
        ttk.Label(
            frame, text="Double-click a report to open it.", font=("Segoe UI", 8), foreground="#888888",
        ).pack(anchor="w", pady=(2, 0))

        ttk.Label(frame, text="Export Log", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(16, 4))
        self.reports_log = tk.Text(frame, height=8, bg="#1e1e2e", fg="#e0e0e0")
        self.reports_log.pack(fill="both", expand=True)

        self._refresh_reports_list()

    def _refresh_reports_list(self):
        """
        Purpose:
            Reload the "Generated Reports" table from whatever files
            actually exist in the reports/ output directory, newest
            first, so past exports are browsable and openable instead of
            only ever being reachable via the one-off success messagebox.
        Parameters:
            None
        Returns:
            None
        """
        self.reports_tree.delete(*self.reports_tree.get_children())
        reports_dir = exporter.REPORTS_DIR
        try:
            entries = [
                (name, os.path.join(reports_dir, name))
                for name in os.listdir(reports_dir)
                if os.path.isfile(os.path.join(reports_dir, name))
            ]
            entries.sort(key=lambda e: os.path.getmtime(e[1]), reverse=True)
        except OSError:
            entries = []

        for name, path in entries:
            ext = os.path.splitext(name)[1].lstrip(".").upper() or "?"
            size_kb = os.path.getsize(path) / 1024
            mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
            self.reports_tree.insert("", "end", iid=path, values=(name, ext, f"{size_kb:.1f} KB", mtime))

    def _open_selected_report(self):
        """
        Purpose:
            Open the currently selected report file in the OS's default
            viewer/application for its file type.
        Parameters:
            None
        Returns:
            None
        """
        selection = self.reports_tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Select a report row first.")
            return
        self._open_path(selection[0])  # the Treeview iid is the full file path

    def _open_reports_folder(self):
        """
        Purpose:
            Open the reports/ output directory in the OS file browser.
        Parameters:
            None
        Returns:
            None
        """
        self._open_path(exporter.REPORTS_DIR)

    def _open_path(self, path: str):
        """
        Purpose:
            Open a file or folder with whatever the OS considers its
            default application (Explorer/Finder/file manager for
            folders, the associated viewer for a PDF/CSV/TXT file).
        Parameters:
            path (str): absolute file or directory path.
        Returns:
            None
        """
        try:
            system = platform.system()
            if system == "Windows":
                os.startfile(path)  # noqa: this attribute only exists on Windows
            elif system == "Darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except Exception as exc:
            messagebox.showerror("Could Not Open", f"Could not open:\n{path}\n\n{exc}")

    def _export_report(self, fmt: str, silent: bool = False):
        """
        Purpose:
            Generate a report in the requested format and log the result.
        Parameters:
            fmt (str): 'pdf' | 'csv' | 'txt'.
            silent (bool): if True, skip the success messagebox (used for
                            auto-export on stop).
        Returns:
            None
        """
        try:
            path = exporter.export(fmt, self._current_network_summary())
            self.reports_log.insert("end", f"[{utils.now_iso()}] Exported {fmt.upper()} report: {path}\n")
            self.reports_log.see("end")
            app_logger.info(f"Exported {fmt.upper()} report to {path}", source="main")
            self._refresh_reports_list()
            if not silent:
                messagebox.showinfo("Export Complete", f"Report saved to:\n{path}")
        except Exception as exc:
            app_logger.error(f"Report export failed: {exc}", source="main")
            if not silent:
                messagebox.showerror("Export Failed", str(exc))

    def _current_network_summary(self) -> dict:
        """
        Purpose:
            Build the plain dict of network context used by exporter.py
            (strips internal helper keys like '_cidr').
        Parameters:
            None
        Returns:
            dict
        """
        return {k: v for k, v in self.network_info.items() if not k.startswith("_")}

    # ------------------------------------------------------------------ #
    # Graphs tab
    # ------------------------------------------------------------------ #
    def _build_graphs_tab(self, frame):
        """
        Purpose:
            Build the Graphs tab: embedded matplotlib charts with a
            refresh button.
        Parameters:
            frame (ttk.Frame): parent frame.
        Returns:
            None
        """
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text="Graphs", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Button(header, text="⟳ Refresh Charts", command=self._refresh_graphs).pack(side="right")

        # Five fixed-size matplotlib figures stacked two-per-row are taller
        # than most window heights, so the bottom chart(s) used to be
        # clipped off with no way to reach them. Embed them in a scrollable
        # canvas instead of packing them straight into the tab.
        scroll_area = ttk.Frame(frame)
        scroll_area.pack(fill="both", expand=True)

        try:
            canvas_bg = self.root.style.colors.bg if TTKBOOTSTRAP_AVAILABLE else self.root.cget("background")
        except Exception:
            canvas_bg = None

        self.graphs_canvas = tk.Canvas(scroll_area, highlightthickness=0, bd=0, background=canvas_bg)
        graphs_scrollbar = ttk.Scrollbar(scroll_area, orient="vertical", command=self.graphs_canvas.yview)
        self.graphs_canvas.configure(yscrollcommand=graphs_scrollbar.set)
        graphs_scrollbar.pack(side="right", fill="y")
        self.graphs_canvas.pack(side="left", fill="both", expand=True)

        self.graphs_container = ttk.Frame(self.graphs_canvas)
        self._graphs_container_window = self.graphs_canvas.create_window(
            (0, 0), window=self.graphs_container, anchor="nw"
        )

        def _on_container_configure(_event):
            # Recompute the scrollable region whenever the chart grid's
            # actual size changes (e.g. after a refresh).
            self.graphs_canvas.configure(scrollregion=self.graphs_canvas.bbox("all"))

        def _on_canvas_configure(event):
            # Keep the inner frame as wide as the visible canvas so the
            # two-column chart grid still fills the tab horizontally.
            self.graphs_canvas.itemconfig(self._graphs_container_window, width=event.width)

        self.graphs_container.bind("<Configure>", _on_container_configure)
        self.graphs_canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(event):
            if platform.system() == "Darwin":
                self.graphs_canvas.yview_scroll(-1 * event.delta, "units")
            else:
                self.graphs_canvas.yview_scroll(-1 * int(event.delta / 120), "units")

        def _on_mousewheel_linux(event):
            self.graphs_canvas.yview_scroll(-1 if event.num == 4 else 1, "units")

        def _bind_mousewheel(_event):
            # Only bind while the pointer is actually over the Graphs tab,
            # so scrolling here doesn't hijack the mouse wheel on other tabs.
            self.graphs_canvas.bind_all("<MouseWheel>", _on_mousewheel)
            self.graphs_canvas.bind_all("<Button-4>", _on_mousewheel_linux)
            self.graphs_canvas.bind_all("<Button-5>", _on_mousewheel_linux)

        def _unbind_mousewheel(_event):
            self.graphs_canvas.unbind_all("<MouseWheel>")
            self.graphs_canvas.unbind_all("<Button-4>")
            self.graphs_canvas.unbind_all("<Button-5>")

        self.graphs_canvas.bind("<Enter>", _bind_mousewheel)
        self.graphs_canvas.bind("<Leave>", _unbind_mousewheel)

        self._graph_canvases = []

        # Build the charts immediately (even if empty placeholders, since
        # there may be no alerts yet) so the tab is never blank on first
        # visit - previously this only happened after the user clicked
        # "Refresh Charts" once.
        self._refresh_graphs()

    def _maybe_auto_refresh_graphs(self, min_interval: float = 3.0):
        """
        Purpose:
            Auto-refresh the Graphs tab in response to new data (a fresh
            alert or a completed scan) without rebuilding the matplotlib
            figures on every single event - rebuilding is somewhat
            expensive, so this throttles to at most once per
            min_interval seconds.
        Parameters:
            min_interval (float): minimum seconds between automatic rebuilds.
        Returns:
            None
        """
        now = time.time()
        if now - self._last_graph_refresh >= min_interval:
            self._refresh_graphs()

    def _refresh_graphs(self):
        """
        Purpose:
            Rebuild and re-embed all four chart types from the latest
            database contents.
        Parameters:
            None
        Returns:
            None
        """
        self._last_graph_refresh = time.time()
        for canvas in self._graph_canvases:
            canvas.get_tk_widget().destroy()
        self._graph_canvases = []

        severity_counts = {
            "info": database.db.count_alerts("info"),
            "warning": database.db.count_alerts("warning"),
            "critical": database.db.count_alerts("critical"),
        }
        category_counts = database.db.alert_category_counts()
        all_devices = database.db.get_all_devices()
        online = database.db.count_devices("online")
        offline = database.db.count_devices("offline")
        unauthorized = sum(1 for d in all_devices if not d["authorized"])
        timeline_rows = database.db.alerts_timeline(limit=200)
        host_ip = self.network_info.get("Host IP", "")
        gateway_ip = self.network_info.get("Gateway IP", "")

        figures = [
            graph.build_alert_severity_pie(severity_counts),
            graph.build_category_bar_chart(category_counts),
            graph.build_device_count_chart(online, offline, unauthorized),
            graph.build_attack_timeline(timeline_rows),
            graph.build_network_topology(host_ip, gateway_ip, all_devices),
        ]

        for i, fig in enumerate(figures):
            cell = ttk.Frame(self.graphs_container)
            cell.grid(row=i // 2, column=i % 2, sticky="nsew", padx=6, pady=6)
            self.graphs_container.grid_columnconfigure(i % 2, weight=1)
            self.graphs_container.grid_rowconfigure(i // 2, weight=1)
            canvas = FigureCanvasTkAgg(fig, master=cell)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
            self._graph_canvases.append(canvas)

    # ------------------------------------------------------------------ #
    # Settings tab
    # ------------------------------------------------------------------ #
    def _build_settings_tab(self, frame):
        """
        Purpose:
            Build the Settings tab: refresh interval, alert sound, auto
            export, network adapter, and theme controls, all backed by
            settings.Settings.
        Parameters:
            frame (ttk.Frame): parent frame.
        Returns:
            None
        """
        ttk.Label(frame, text="Settings", font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(0, 16))

        # Explicit style for the numeric Spinboxes below: a fixed, larger
        # font guarantees the numbers stay clearly legible on every
        # machine, instead of silently inheriting whatever tiny default
        # size the current theme/Windows DPI setting happens to produce
        # (the cause of the numbers being hard to read on some laptops).
        style = ttk.Style()
        spin_font = ("Segoe UI", 12)
        style.configure("Settings.TSpinbox", font=spin_font, padding=(4, 4))

        form = ttk.Frame(frame)
        form.pack(anchor="w", fill="x")

        # Refresh interval
        ttk.Label(form, text="Refresh Interval (seconds):", font=("Segoe UI", 11)).grid(
            row=0, column=0, sticky="w", pady=6
        )
        self.refresh_interval_var = tk.IntVar(value=settings.get("refresh_interval", 5))
        ttk.Spinbox(
            form, from_=1, to=60, textvariable=self.refresh_interval_var, width=10,
            style="Settings.TSpinbox", font=spin_font,
        ).grid(row=0, column=1, sticky="w")

        # Alert sound
        self.alert_sound_var = tk.BooleanVar(value=settings.get("alert_sound", True))
        ttk.Checkbutton(form, text="Play alert sound", variable=self.alert_sound_var).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=6
        )

        # Desktop notifications
        self.desktop_notif_var = tk.BooleanVar(value=settings.get("desktop_notifications", True))
        ttk.Checkbutton(form, text="Show desktop notifications", variable=self.desktop_notif_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=6
        )

        # Auto export
        self.auto_export_var = tk.BooleanVar(value=settings.get("auto_export", False))
        ttk.Checkbutton(form, text="Auto-export report when monitoring stops", variable=self.auto_export_var).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=6
        )
        ttk.Label(form, text="Auto-export format:").grid(row=4, column=0, sticky="w")
        self.auto_export_fmt_var = tk.StringVar(value=settings.get("auto_export_format", "csv"))
        ttk.Combobox(
            form, textvariable=self.auto_export_fmt_var, values=["csv", "pdf", "txt"], width=8, state="readonly"
        ).grid(row=4, column=1, sticky="w")

        # Network adapter
        ttk.Label(form, text="Network Adapter:").grid(row=5, column=0, sticky="w", pady=6)
        self.adapter_var = tk.StringVar(value=settings.get("network_adapter", "auto"))
        adapter_choices = ["auto"] + self.scanner.list_interfaces()
        ttk.Combobox(form, textvariable=self.adapter_var, values=adapter_choices, width=30, state="readonly").grid(
            row=5, column=1, sticky="w"
        )

        # Theme
        ttk.Label(form, text="Theme:").grid(row=6, column=0, sticky="w", pady=6)
        self.theme_var = tk.StringVar(value=settings.get("theme", "dark"))
        ttk.Combobox(
            form, textvariable=self.theme_var, values=["dark", "light"], width=8, state="readonly"
        ).grid(row=6, column=1, sticky="w")

        # Active probe interval (keeps Live Monitor/Graphs fed with real
        # traffic while monitoring is running - see Dashboard tab note)
        ttk.Label(form, text="Active Probe Interval while monitoring (seconds):").grid(
            row=7, column=0, sticky="w", pady=6
        )
        self.probe_interval_var = tk.IntVar(value=settings.get("live_probe_interval", 6))
        ttk.Spinbox(form, from_=2, to=60, textvariable=self.probe_interval_var, width=8).grid(
            row=7, column=1, sticky="w"
        )

        ttk.Button(frame, text="💾 Save Settings", command=self._save_settings).pack(anchor="w", pady=16)

        # Authorized devices management
        auth_frame = ttk.Labelframe(frame, text="Authorized Devices")
        auth_frame.pack(fill="both", expand=True, pady=(10, 0))
        self.auth_list = tk.Listbox(auth_frame, height=8)
        self.auth_list.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=8)
        self._refresh_authorized_list()
        ttk.Button(auth_frame, text="Remove Selected", command=self._remove_authorized_device).pack(
            side="left", padx=8, pady=8, anchor="n"
        )

    def _refresh_authorized_list(self):
        """
        Purpose:
            Repopulate the authorized-devices listbox from settings.
        Parameters:
            None
        Returns:
            None
        """
        self.auth_list.delete(0, "end")
        for d in settings.get("authorized_devices", []):
            self.auth_list.insert("end", f"{d.get('ip', '')}  {d.get('mac', '')}  {d.get('label', '')}")

    def _remove_authorized_device(self):
        """
        Purpose:
            Remove the selected device from the authorized whitelist.
        Parameters:
            None
        Returns:
            None
        """
        selection = self.auth_list.curselection()
        if not selection:
            return
        text = self.auth_list.get(selection[0])
        mac = text.split()[1] if len(text.split()) > 1 else ""
        settings.remove_authorized_device(mac)
        self._refresh_authorized_list()

    def _save_settings(self):
        """
        Purpose:
            Persist all Settings-tab form values back into settings.Settings.
        Parameters:
            None
        Returns:
            None
        """
        settings.set("refresh_interval", self.refresh_interval_var.get(), persist=False)
        settings.set("alert_sound", self.alert_sound_var.get(), persist=False)
        settings.set("desktop_notifications", self.desktop_notif_var.get(), persist=False)
        settings.set("auto_export", self.auto_export_var.get(), persist=False)
        settings.set("auto_export_format", self.auto_export_fmt_var.get(), persist=False)
        settings.set("network_adapter", self.adapter_var.get(), persist=False)
        settings.set("live_probe_interval", self.probe_interval_var.get(), persist=False)
        settings.set("theme", self.theme_var.get(), persist=True)

        if TTKBOOTSTRAP_AVAILABLE:
            new_theme = THEME_MAP.get(self.theme_var.get(), "cyborg")
            try:
                self.root.style.theme_use(new_theme)
            except Exception as exc:
                app_logger.warning(f"Could not switch theme live: {exc}", source="main")
        else:
            messagebox.showinfo(
                "Theme Not Applied",
                "The 'ttkbootstrap' package is not installed, so only the default plain "
                "Tk/ttk styling is available. Install it with:\n\npip install ttkbootstrap\n\n"
                "and restart the app to see the dark/light theme.",
            )

        messagebox.showinfo("Settings Saved", "Your settings have been saved.")
        self._set_status("Settings saved.")

    # ------------------------------------------------------------------ #
    # About tab
    # ------------------------------------------------------------------ #
    def _build_about_tab(self, frame):
        """
        Purpose:
            Build the About tab with project information.
        Parameters:
            frame (ttk.Frame): parent frame.
        Returns:
            None
        """
        ttk.Label(frame, text="About", font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(0, 12))

        ttk.Label(
            frame, text="Real-Time ARP Spoofing Detection & LAN Intrusion Monitoring System",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            frame, text="Academic Project - First Semester (PJW)",
            font=("Segoe UI", 10, "italic"), foreground="#5dade2",
        ).pack(anchor="w", pady=(2, 14))

        intro = (
            "This tool passively observes ARP traffic on the local network to detect spoofing "
            "and intrusion patterns such as MAC changes, duplicate IP claims, fake gateway "
            "impersonation, gratuitous ARP floods, and broadcast storms. It never sends spoofed "
            "packets itself - it is a defensive monitoring tool only."
        )
        ttk.Label(frame, text=intro, justify="left", wraplength=950).pack(anchor="w", pady=(0, 16))

        features_frame = ttk.Labelframe(frame, text="Key Features")
        features_frame.pack(fill="x", pady=(0, 14))
        features = [
            "Live network discovery and device inventory (with a no-privilege fallback scan)",
            "Real-time ARP monitoring, kept active with periodic background sweeps",
            "Six detection rules: MAC change, duplicate IP, unknown device, fake gateway, "
            "gratuitous ARP flood, and broadcast storm",
            "Desktop notifications and in-app alert popups with sound",
            "PDF / CSV / TXT report export with a browsable report history",
            "Dashboards: severity breakdown, threat frequency, device count, attack "
            "timeline, and network topology",
            "A safe, synthetic Demo Scenario for presentations - no second attacking machine needed",
        ]
        for f in features:
            ttk.Label(features_frame, text=f"• {f}", justify="left", wraplength=920).pack(
                anchor="w", padx=10, pady=2
            )

        ttk.Label(
            frame, text="Built with Python, Tkinter/ttkbootstrap, Scapy, Matplotlib, NetworkX, "
                        "ReportLab, and SQLite.",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 4))
        ttk.Label(
            frame,
            text="Full raw-socket ARP scanning and packet capture need administrator/root "
                 "privileges; a no-privilege ping + ARP-cache fallback is used automatically "
                 "when those aren't available.",
            font=("Segoe UI", 8), foreground="#888888", wraplength=950,
        ).pack(anchor="w")

    # ------------------------------------------------------------------ #
    # Network discovery (runs on the GUI thread at startup / on demand,
    # but the ARP portion is dispatched to a worker thread so a slow LAN
    # sweep never freezes the window)
    # ------------------------------------------------------------------ #
    def _discover_network(self, initial: bool):
        """
        Purpose:
            Populate self.network_info with host/gateway/adapter details
            and kick off an initial device scan.
        Parameters:
            initial (bool): True on application startup (adjusts messaging).
        Returns:
            None
        """
        self._set_status("Discovering network..." if not initial else "Starting up - discovering network...")

        def worker():
            iface, ip = self.scanner.get_active_interface()
            mac = self.scanner.get_local_mac(iface) if iface else ""
            netmask = self.scanner.get_subnet_mask(iface) if iface else ""
            cidr = self.scanner.get_network_cidr(ip, netmask) if ip and netmask else ""
            gateway_ip = self.scanner.get_default_gateway()
            gateway_mac = self.scanner.get_gateway_mac(gateway_ip, cidr) if gateway_ip and cidr else ""

            info = {
                "Current Network Adapter": iface or "N/A",
                "Host IP": ip or "N/A",
                "Host MAC Address": mac or "N/A",
                "Gateway IP": gateway_ip or "N/A",
                "Gateway MAC": gateway_mac or "N/A",
                "Hostname": self.scanner.get_hostname(),
                "Operating System": self.scanner.get_os_info(),
                "Subnet Mask": netmask or "N/A",
                "_cidr": cidr,
            }
            self.event_queue.put(("network_info", info))

            if cidr:
                try:
                    found = self.scanner.arp_scan(cidr, timeout=3)
                    for d in found:
                        database.db.upsert_device(
                            d["ip"], d["mac"], vendor=d["vendor"], hostname=d["hostname"],
                            status="online", authorized=settings.is_authorized(d["mac"]),
                        )
                    self.event_queue.put(("scan_done", (len(found), self.scanner.last_scan_method)))
                except Exception as exc:
                    self.event_queue.put(("scan_error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------ #
    # GUI update loop
    # ------------------------------------------------------------------ #
    def _tick(self):
        """
        Purpose:
            Periodic timer callback (runs on the main/GUI thread only):
            updates the clock, drains the background-thread event queue,
            and refreshes the blinking alert indicator.
        Parameters:
            None
        Returns:
            None
        """
        self.dashboard_vars["System Time"].set(utils.now_time_only())
        self._drain_queue()

        if notifier.blink_state.is_active():
            blink_on = int(time.time() * 2) % 2 == 0
            self.blink_label.config(
                text="⚠ ACTIVE THREAT DETECTED" if blink_on else "", foreground="#e74c3c"
            )
        else:
            self.blink_label.config(text="")

        self.root.after(REFRESH_MS, self._tick)

    def _drain_queue(self):
        """
        Purpose:
            Process every pending event pushed by background threads
            (network discovery results, ARP scan completion, live packets,
            alerts, stats) and apply them to the GUI. This is the ONLY
            place background-thread data is allowed to touch widgets.
        Parameters:
            None
        Returns:
            None
        """
        while True:
            try:
                kind, payload = self.event_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "network_info":
                self.network_info = payload
                for key in ("Current Network Adapter", "Host IP", "Host MAC Address", "Gateway IP", "Gateway MAC"):
                    self.dashboard_vars[key].set(payload.get(key, "N/A"))
                self.dashboard_vars["Monitoring Status"].set("STOPPED")
                self._set_status("Network discovery complete.")

            elif kind == "scan_done":
                count, method = payload
                self._refresh_devices_table()
                note = " (no-admin fallback mode - ping + ARP cache)" if method == "fallback" else ""
                self._set_status(f"Scan complete - {count} device(s) found{note}.")
                self._maybe_auto_refresh_graphs()

            elif kind == "scan_error":
                self._set_status(f"Scan error: {payload}")

            elif kind == "packet":
                self._append_live_packet(payload)

            elif kind == "stats":
                count, pps = payload
                self.packets_seen = count
                self.pps_current = pps
                self.dashboard_vars["Packets Captured"].set(str(count))
                self.dashboard_vars["Live Traffic"].set(utils.format_rate(count, count / pps if pps else 1))

            elif kind == "alert":
                self._handle_new_alert(payload)

    def _handle_new_alert(self, alert: dict):
        """
        Purpose:
            React to a new alert delivered from the detector: refresh the
            Alerts tables, show the popup/sound/notification, and take a
            periodic statistics snapshot for the trend chart.
        Parameters:
            alert (dict): alert data (severity, category, message, ip, mac).
        Returns:
            None
        """
        self._refresh_alerts_table()

        self.recent_alerts_tree.insert(
            "", 0, values=(alert["timestamp"][11:19], alert["severity"].upper(), alert["category"], alert["message"])
        )
        children = self.recent_alerts_tree.get_children()
        if len(children) > 8:
            self.recent_alerts_tree.delete(children[-1])

        notifier.show_alert_popup(self.root, alert)

        try:
            database.db.snapshot_statistics(
                utils.now_iso(), self.packets_seen, database.db.count_devices("online"),
                database.db.count_alerts(), database.db.count_alerts("critical"),
            )
        except Exception as exc:
            app_logger.warning(f"Could not snapshot statistics: {exc}", source="main")

        self._maybe_auto_refresh_graphs()

    def _set_status(self, text: str):
        """
        Purpose:
            Update the bottom status bar text.
        Parameters:
            text (str): message to display.
        Returns:
            None
        """
        self.status_bar.config(text=f"{utils.now_time_only()}  |  {text}")

    def run(self):
        """
        Purpose:
            Start the Tkinter main event loop (blocking call).
        Parameters:
            None
        Returns:
            None
        """
        self.root.mainloop()


def main():
    """
    Purpose:
        Application entry point: create the ARP_Monitor working
        directories if missing, log startup, and launch the GUI.
    Parameters:
        None
    Returns:
        None
    """
    # Make Windows render this app at the display's real pixel resolution
    # instead of drawing it at a fixed low-DPI size and letting Windows
    # bitmap-stretch it to fit the screen's scaling setting. Tk itself has
    # no idea this happens - to Tk everything looks normal - but on a
    # laptop with scaling above 100% (125%/150%/175%, extremely common on
    # small high-resolution screens) the stretched result is blurry, and
    # small text like Spinbox numbers can become genuinely hard to read
    # or look cut off. This must run before any Tk window is created.
    if platform.system() == "Windows":
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
        except Exception:
            try:
                windll.user32.SetProcessDPIAware()  # older Windows fallback
            except Exception:
                pass

    base = os.path.dirname(os.path.abspath(__file__))
    for sub in ("database", "reports", "logs", "screenshots", "assets"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)

    app_logger.info("Application starting.", source="main")
    app = ArpMonitorApp()
    app.run()
    app_logger.info("Application closed.", source="main")


if __name__ == "__main__":
    main()
