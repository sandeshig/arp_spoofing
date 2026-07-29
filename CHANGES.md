# ARP Monitor — Fixes & Improvements

## 1. Devices tab was empty
**Cause:** Device discovery relied entirely on scapy's raw-socket ARP sweep
(`scanner.arp_scan`), which needs admin/root privileges plus Npcap
(Windows) or libpcap (Linux/macOS) correctly installed. If either was
missing, the scan failed silently and the tab just stayed empty.

**Fix (`scanner.py`):** Added a no-privilege fallback scan method. If the
raw-socket sweep isn't available or fails for any reason, the app now:
1. Ping-sweeps every host in the subnet (a plain OS `ping`, no raw socket
   needed) so each live host lands in the operating system's own ARP /
   neighbor cache.
2. Reads that cache back (`arp -a` on Windows/macOS, `ip neigh show` on
   Linux) and returns the same `{ip, mac, vendor, hostname, last_seen}`
   shape the rest of the app expects.

This runs automatically — nothing to configure — and `scanner.last_scan_method`
records which path was used (`"scapy"` or `"fallback"`) so the status bar can
tell you which one ran.

## 2. Reports tab was "just buttons"
**Fix (`main.py`):** Added a **Generated Reports** list under the export
buttons showing every past PDF/CSV/TXT export (name, format, size, date),
with **Open Selected**, **Open Reports Folder**, and **Refresh List**
buttons, plus double-click-to-open. It refreshes automatically after every
new export.

## 3. "Start Monitoring" showed nothing without repeatedly running the demo
**Cause:** This was real, not a misunderstanding — the packet sniffer only
reacts to organic ARP traffic on the wire, which is genuinely sparse on a
quiet network. Live Monitor / Graphs stayed empty until you manually ran
"Run Demo Scenario."

**Fix (`main.py`):** Starting monitoring now also launches a background
**active prober** thread that periodically re-sweeps the LAN (the same
`scanner.arp_scan` used by "Scan Now"). The broadcast ARP requests this
sends prompt real reply traffic from real devices, which the sniffer
thread picks up and feeds through the exact same detection code as any
organic packet — so Live Monitor, the packet counters, and the graphs
keep filling with **genuine** data continuously, not synthetic data, and
not only during a demo. The interval is configurable in Settings
("Active Probe Interval while monitoring").

As a side effect, this loop also keeps device online/offline status
current: any device that stops responding for two consecutive sweeps is
marked offline in the Devices tab.

## 4. Graphs only appeared after running a simulation / needed manual refresh
**Cause:** An actual bug — `_build_graphs_tab` never called its own
chart-building function when the tab was first built, and nothing
triggered a rebuild after new alerts arrived. The charts only ever updated
on the manual "Refresh Charts" click.

**Fix (`main.py`):** Charts now build immediately when the app starts
(showing "No alerts yet" placeholders if there's no data), auto-refresh
whenever a new alert fires or a scan completes (throttled to once per ~3s
so it doesn't rebuild on every single packet), and refresh again whenever
you switch to the Graphs tab as an extra safety net.

## 5. About tab
Corrected "final year project" to "Academic Project — First Semester (PJW)"
and reorganized the tab with a features list and tech-stack line.

## Other small improvements
- `get_gateway_mac` also benefits from the new fallback path, so the
  gateway's MAC (used for fake-gateway/MITM detection) can still be
  resolved without scapy/admin rights.
- The active-prober thread is bound to its own stop-event instance so a
  quick Stop → Start click can't leave an orphaned background thread
  running.
- Added a `live_probe_interval` setting (default 6s), editable from the
  Settings tab.

## 6. An alert named a device that never showed up in the Devices tab
**Cause:** Two separate mechanisms were never linked. `detector.py`
passively sniffs ARP traffic and raises an alert (e.g. `UNKNOWN_DEVICE`)
for any IP/MAC it observes on the wire — that only requires read access
to the interface. Populating the *Devices* tab, on the other hand, was
left entirely to the active `scanner.arp_scan()` sweep (run on a timer
by the active prober, or on demand via "Scan Now") — which needs
raw-socket **send** privileges, and on its no-privilege fallback path
only finds hosts that answer an ICMP ping. A phone or IoT device that
ignores ping, or a scan running without admin/root, could be seen and
alerted on by the sniffer while never making it into the device list.

**Fix (`detector.py`):** The moment `_check_mapping_change` sees a
brand-new IP for the first time, it now calls
`database.db.upsert_device(...)` directly (vendor looked up from the
MAC), independent of whether any active scan ever reaches that host.
The Devices tab (refreshed on its normal timer) will show it on the
next refresh, whether or not the active sweep can reach it.

**Note:** this is unrelated to router brand — the whole app works at
the IP/ARP layer and the same way regardless of whether the gateway is
a Cisco, TP-Link, or anything else. If a device *still* doesn't show up
even after this fix, check whether your router/access point has
"AP isolation" / "client isolation" turned on for Wi-Fi — that setting
blocks devices from ARPing each other directly at the router itself, so
no ARP traffic for that device ever reaches this host to observe.

## 7. No obvious way to select a device for "Authorize Selected"
**Cause:** The button relied entirely on ttk.Treeview's built-in row
selection (click a row to highlight it) with no visible affordance -
easy to miss, and only one row at a time.

**Fix (`main.py`):** Added a real "Select" checkbox column to the
Devices table (☐/☑, toggled with a click) plus a hint label above the
table. "Authorize Selected" now authorizes every checked device; if
none are checked it falls back to the old row-selection behavior, so
both ways of picking a device still work.

## 8. Graphs tab clipped the bottom chart(s) with no way to reach them
**Cause:** All five charts (each a fixed-size matplotlib figure) were
packed straight into the tab in a 2-column grid with no scrolling
mechanism. Stacked up, they're taller than most window heights, so
anything past the second row was simply cut off.

**Fix (`main.py`):** The chart grid now lives inside a scrollable
Tkinter canvas with a vertical scrollbar and mouse-wheel support
(Windows/macOS/Linux), so every chart is reachable regardless of window
size.

## 7. Devices flickered to "Offline" while clearly still active (games/apps running)
**Cause:** The active prober's offline-marking loop only trusted its own
ping-based probe. A device that simply doesn't answer ICMP/ARP probes
(very common for phones, consoles, and IoT gear, and *guaranteed* if the
scan is running without admin/root and fell back to the ping-sweep
method) got counted as "missed" and flipped offline after two probe
cycles, even while it was still actively sending real traffic the
passive detector could see just fine.

**Fix (`detector.py`, `main.py`):** The passive detector now refreshes a
device's `status`/`last_seen` on every sighting (throttled to once per
~5s per device), not just the first time it's seen. The active prober's
offline-marking loop now also checks each device's `last_seen` before
flipping it offline, and skips the flip if anything (passive or active)
touched it more recently than roughly two probe cycles. A missed ping
alone no longer overrides real, ongoing traffic.

**Fix (`database.py`):** `upsert_device` no longer blanks out a
previously-resolved vendor/hostname when a later call (e.g. a quick
passive sighting) doesn't have one to offer - it now keeps the existing
value instead of overwriting it with an empty string.

## 8. Hard to tell how to check a device to authorize it
**Cause:** The Select column had a blank header and only responded to
clicks in its own narrow ~60px cell, so it wasn't obvious the column was
interactive at all.

**Fix (`main.py`):** The column now has a visible "Select" header, and
clicking **anywhere on a device's row** toggles its checkbox (not just
that narrow cell) - click again to uncheck. Check as many rows as you
want, then click "Authorize Selected".

## 9. Demo scenario didn't reliably show all three alert severities (info / warning / critical)
**Cause:** Two separate bugs in `demo_simulator.py`:
1. The fake-gateway (MITM) step only raises an alert by comparing against
   `detector_instance.gateway_ip`/`gateway_mac` on the *real* detector
   object - but if the app's own network detection never resolved a
   gateway (e.g. it needs admin/root and fell back to a no-privilege
   scan on a given machine), those fields are blank and
   `_check_fake_gateway()` bails out immediately. That silently dropped
   the demo's clearest CRITICAL example.
2. The gratuitous-ARP-flood step (the intended "medium"/WARNING example)
   fired each of its 8 packets one full `delay` (1 second, by default)
   apart. The flood detector only counts packets inside a rolling
   1-second window, so packets arriving exactly ~1s apart never
   accumulated past the threshold - this alert could mathematically
   never fire at the demo's default pacing.

**Fix (`demo_simulator.py`):** `run_demo_scenario()` now writes its own
gateway IP/MAC back onto the detector instance before the scenario runs,
so the fake-gateway/MITM step fires regardless of what real-network
detection found. The gratuitous-flood burst is now paced on its own
short fixed interval, independent of the human-readable `delay` used
elsewhere in the story, so it reliably lands inside the detector's
1-second window. Verified with an automated before/after test: with an
unresolved gateway, the original code produced only
`info: 1, warning: 2, critical: 1` (missing the flood alert entirely);
the fixed version reliably produces `info: 1, warning: 3, critical: 2`
on every run.

## 10. Settings tab numbers hard to read on some laptops
**Cause:** The Refresh Interval / Active Probe Interval Spinboxes had no
explicit font, so their text size was left entirely to the OS ttk
theme's default - on a laptop with Windows display scaling above 100%
(125%/150%/175%, very common on small high-resolution screens), Tk has
no awareness of the real pixel density unless the process explicitly
opts in, so Windows silently bitmap-stretches the whole window and text
comes out blurry or too small to read clearly.

**Fix (`main.py`):** The app now requests Windows DPI awareness
(`SetProcessDpiAwareness`) before creating the root window, so Tk renders
at the display's real resolution instead of being scaled after the fact.
The two Spinboxes also get an explicit, fixed 12pt font via a dedicated
`Settings.TSpinbox` style, so the numbers stay a guaranteed, legible size
regardless of theme or DPI setting.

## 11. No way to remove a device's authorization from the Devices tab
**Cause:** Removing a device from the authorized whitelist only existed
as a "Remove Selected" button tied to the Settings tab's plain listbox
(identify the device by its MAC text string) - there was no way to do it
from the Devices tab, where you're already looking at the device.

**Fix (`main.py`):** Added a "✖ Remove Authorization" button next to
"✔ Authorize Selected" in the Devices tab, using the exact same
click-a-row-to-check UX. Authorizing/de-authorizing from either tab now
keeps both views in sync.

**Fix (`database.py`):** Both actions now call a new
`set_device_authorized(mac, bool)` helper that updates only the
`authorized` column. Previously both flows re-used `upsert_device()`,
which defaults `status="online"` and always bumps `last_seen` - so
authorizing (or de-authorizing) a device that was currently offline
silently marked it "online" again as a side effect.

## 12. Devices tab didn't show a device's name
**Cause:** `hostname` was already being resolved by the scanner and
stored in the database for every device, but the Devices table simply
never displayed that column.

**Fix (`main.py`):** Added a "Device Name" column (bound to the
existing `hostname` field) to the Devices tab table, shown right after
IP/MAC.

## 13. Live Monitor showed newest packets at the bottom
**Cause:** New packet rows were always inserted at the end of the
table, so watching live traffic meant the newest activity was always
off-screen below whatever was currently visible.

**Fix (`main.py`):** New rows are now inserted at the top, so the most
recent packet is always the first one visible; the row-count cap now
trims from the bottom (the oldest row) instead of the top to match.
Live **packet capture** itself (the sniffing detector) genuinely requires
scapy + admin/root + Npcap/libpcap — there's no safe way around that for
raw packet sniffing on any OS. The fixes above solve the *practical*
symptoms (empty Devices tab, empty Live Monitor, static Graphs) but if
"Start Monitoring" still shows a "Scapy Not Available" error, you'll need
to run the app as Administrator (Windows) / with sudo (Linux/macOS) with
scapy and Npcap/libpcap installed.
