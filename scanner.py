"""
scanner.py
==========
Network discovery: finds the local IP, subnet, gateway, active network
adapter, and performs active ARP scans to enumerate live devices on the
LAN.

Scapy is used for the active ARP scan (it needs raw socket / npcap
access and admin/root privileges). Everything else uses only the
standard library plus psutil, so the rest of the app degrades gracefully
even in a restricted environment.
"""

import re
import socket
import platform
import subprocess
import ipaddress
import threading
import concurrent.futures

import psutil

from utils import normalize_mac, lookup_vendor, now_iso, is_valid_mac
from logger import app_logger

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    # The app can still run (dashboard, DB, reports, graphs) without scapy;
    # only live capture/scan features are disabled until it's installed.
    SCAPY_AVAILABLE = False


class NetworkScanner:
    """Discovers local network parameters and performs ARP sweeps."""

    def __init__(self, settings_obj):
        """
        Purpose:
            Store a reference to the shared Settings object (used to read
            the configured network adapter, if the user pinned one).
        Parameters:
            settings_obj: an instance of settings.Settings.
        Returns:
            None
        """
        self.settings = settings_obj
        self._lock = threading.Lock()
        # Set after every arp_scan() call so the GUI can tell the user
        # whether the fast raw-socket method or the no-privilege
        # ping+ARP-cache fallback produced the results.
        self.last_scan_method = "scapy"

    # ------------------------------------------------------------------ #
    # Host / adapter discovery
    # ------------------------------------------------------------------ #
    def get_hostname(self) -> str:
        """
        Purpose:
            Get this machine's hostname for the dashboard.
        Parameters:
            None
        Returns:
            str: hostname, or 'unknown-host' on failure.
        """
        try:
            return socket.gethostname()
        except Exception:
            return "unknown-host"

    def get_os_info(self) -> str:
        """
        Purpose:
            Get a short OS description string for the dashboard/report.
        Parameters:
            None
        Returns:
            str: e.g. "Windows-11", "Linux-6.8.0", "Darwin-23.5.0".
        """
        try:
            return f"{platform.system()}-{platform.release()}"
        except Exception:
            return platform.system() or "unknown-os"

    def get_active_interface(self):
        """
        Purpose:
            Choose which network interface to monitor: either the one the
            user pinned in Settings, or the first interface that is UP and
            has an IPv4 address that isn't loopback.
        Parameters:
            None
        Returns:
            tuple(str, str) | (None, None): (interface_name, ipv4_address)
        Workflow:
            1. If settings has a specific adapter configured, verify it's
               still present and up; use it if so.
            2. Otherwise iterate psutil.net_if_addrs() / net_if_stats()
               and return the first UP, non-loopback IPv4 interface.
        """
        pinned = self.settings.get("network_adapter", "auto")
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        def ipv4_of(if_name):
            for snic in addrs.get(if_name, []):
                if snic.family == socket.AF_INET and not snic.address.startswith("127."):
                    return snic.address
            return None

        if pinned and pinned != "auto" and pinned in addrs:
            if stats.get(pinned) and stats[pinned].isup:
                ip = ipv4_of(pinned)
                if ip:
                    return pinned, ip

        for if_name, if_stats in stats.items():
            if not if_stats.isup:
                continue
            ip = ipv4_of(if_name)
            if ip:
                return if_name, ip

        return None, None

    def list_interfaces(self):
        """
        Purpose:
            List all available network interface names for the Settings
            tab's adapter dropdown.
        Parameters:
            None
        Returns:
            list[str]: interface names.
        """
        return list(psutil.net_if_addrs().keys())

    def get_local_mac(self, interface: str) -> str:
        """
        Purpose:
            Get the MAC address of the given interface (this host's MAC).
        Parameters:
            interface (str): interface name as reported by psutil.
        Returns:
            str: normalized MAC address, or "" if unavailable.
        """
        addrs = psutil.net_if_addrs().get(interface, [])
        for snic in addrs:
            # AF_LINK on macOS/BSD, AF_PACKET(17) on Linux, -1/AddressFamily on Windows psutil builds
            if snic.family in (getattr(socket, "AF_PACKET", -1), getattr(psutil, "AF_LINK", -1)):
                return normalize_mac(snic.address)
        # Fallback: some platforms report the MAC alongside AF_INET entries
        for snic in addrs:
            if snic.address and len(snic.address.replace(":", "").replace("-", "")) == 12:
                return normalize_mac(snic.address)
        return ""

    def get_subnet_mask(self, interface: str) -> str:
        """
        Purpose:
            Get the IPv4 subnet mask for the given interface.
        Parameters:
            interface (str): interface name.
        Returns:
            str: dotted-decimal netmask, or "" if unavailable.
        """
        for snic in psutil.net_if_addrs().get(interface, []):
            if snic.family == socket.AF_INET:
                return snic.netmask or ""
        return ""

    def get_network_cidr(self, ip: str, netmask: str) -> str:
        """
        Purpose:
            Compute the CIDR network (e.g. "192.168.1.0/24") for the ARP
            scan target range, from a host IP and its netmask.
        Parameters:
            ip (str): host IPv4 address.
            netmask (str): dotted-decimal netmask.
        Returns:
            str: CIDR network string, or "" on failure.
        """
        try:
            iface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
            return str(iface.network)
        except (ValueError, ipaddress.AddressValueError):
            return ""

    def get_default_gateway(self):
        """
        Purpose:
            Determine the default gateway IP address in a cross-platform
            way, without any third-party "route" library.
        Parameters:
            None
        Returns:
            str: gateway IPv4 address, or "" if it could not be determined.
        Workflow:
            - Windows: parse `ipconfig` output for "Default Gateway".
            - Linux/macOS: parse `ip route` / `netstat -rn` output.
            Falls back gracefully to "" if parsing fails, so callers must
            handle the empty-string case.
        """
        system = platform.system()
        try:
            if system == "Windows":
                out = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
                for line in out.splitlines():
                    if "Default Gateway" in line and ":" in line:
                        candidate = line.split(":", 1)[1].strip()
                        if candidate and candidate != "":
                            return candidate
            elif system == "Linux":
                out = subprocess.check_output(["ip", "route", "show", "default"], text=True, errors="ignore")
                parts = out.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
            else:  # Darwin / other BSD-likes
                out = subprocess.check_output(["netstat", "-rn"], text=True, errors="ignore")
                for line in out.splitlines():
                    if line.startswith("default"):
                        return line.split()[1]
        except Exception as exc:
            app_logger.warning(f"Could not determine default gateway automatically: {exc}", source="scanner")
        return ""

    def resolve_hostname(self, ip: str) -> str:
        """
        Purpose:
            Reverse-resolve an IP address to a hostname for the device
            table (best-effort, short timeout via socket default).
        Parameters:
            ip (str): IPv4 address to resolve.
        Returns:
            str: hostname if resolvable, otherwise "".
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return ""

    # ------------------------------------------------------------------ #
    # Active ARP sweep
    # ------------------------------------------------------------------ #
    def arp_scan(self, cidr: str, timeout: int = 3):
        """
        Purpose:
            Actively sweep a CIDR range to enumerate live devices. Tries
            the fast raw-socket ARP sweep first, and transparently falls
            back to a no-privilege ping+ARP-cache method if that isn't
            available - so the Devices tab still populates on a normal,
            non-elevated setup instead of silently coming back empty.
        Parameters:
            cidr (str): network range to scan, e.g. "192.168.1.0/24".
            timeout (int): seconds to wait for replies.
        Returns:
            list[dict]: one dict per responding device with keys
                        'ip', 'mac', 'vendor', 'hostname', 'last_seen'.
        Workflow:
            1. If scapy is installed, build a broadcast ARP request
               Ether/ARP packet for the range and collect replies with
               scapy.srp() - this is the fastest, most complete method,
               but needs raw-socket privileges (admin/root + Npcap/libpcap).
            2. If scapy isn't installed, or step 1 fails for any reason
               (most commonly: not running elevated, or Npcap/libpcap not
               set up), fall back to arp_scan_fallback(): ping every host
               in the range (which doesn't need raw sockets) so each live
               host lands in the OS's own ARP/neighbor cache, then read
               that cache back. Slightly slower and slightly less
               complete (only finds hosts that answer ICMP), but it works
               without any elevated privileges.
            self.last_scan_method records which path was used ('scapy' or
            'fallback') so the GUI can tell the user which one ran.
        """
        if not cidr:
            return []

        if SCAPY_AVAILABLE:
            with self._lock:
                try:
                    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
                    answered, _unanswered = srp(request, timeout=timeout, verbose=False)
                    devices = []
                    for _sent, received in answered:
                        ip = received.psrc
                        mac = normalize_mac(received.hwsrc)
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "vendor": lookup_vendor(mac),
                            "hostname": self.resolve_hostname(ip),
                            "last_seen": now_iso(),
                        })
                    self.last_scan_method = "scapy"
                    return devices
                except PermissionError as exc:
                    app_logger.warning(
                        f"Raw-socket ARP scan needs admin/root privileges ({exc}); "
                        "using the no-privilege ping+ARP-cache fallback instead.",
                        source="scanner",
                    )
                except Exception as exc:
                    app_logger.warning(
                        f"Raw-socket ARP scan failed ({exc}); using the no-privilege "
                        "ping+ARP-cache fallback instead.", source="scanner",
                    )
        else:
            app_logger.info(
                "scapy is not installed - using the no-privilege ping+ARP-cache scan method.",
                source="scanner",
            )

        self.last_scan_method = "fallback"
        return self.arp_scan_fallback(cidr, timeout=timeout)

    # ------------------------------------------------------------------ #
    # No-privilege fallback discovery (ping sweep + OS ARP/neighbor cache)
    # ------------------------------------------------------------------ #
    def _ping_once(self, ip: str, timeout_s: float = 1.0) -> bool:
        """
        Purpose:
            Ping a single host using the OS's own `ping` command. This
            never needs raw-socket/admin privileges (unlike opening a raw
            ICMP or ARP socket directly), so it is safe to use as the
            no-privilege discovery method's probe step.
        Parameters:
            ip (str): target IPv4 address.
            timeout_s (float): how long to wait for a reply.
        Returns:
            bool: True if the host replied, False otherwise (including on
                  any error - this is a best-effort reachability probe).
        """
        system = platform.system()
        try:
            if system == "Windows":
                cmd = ["ping", "-n", "1", "-w", str(max(100, int(timeout_s * 1000))), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_s)))), ip]
            result = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s + 1,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _ping_sweep(self, cidr: str, timeout_s: float = 1.0, max_workers: int = 40) -> None:
        """
        Purpose:
            Ping every host address in the CIDR range concurrently. This
            doesn't discover devices by itself - its job is to make sure
            every live host gets a fresh entry in the OS's own ARP/
            neighbor cache, since an OS only ARPs for an address it has
            recently tried to talk to.
        Parameters:
            cidr (str): network range to sweep, e.g. "192.168.1.0/24".
            timeout_s (float): per-host ping timeout.
            max_workers (int): concurrency cap so a big/misconfigured
                                range doesn't spawn hundreds of processes.
        Returns:
            None
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return
        hosts = list(network.hosts())
        if len(hosts) > 1024:  # safety cap for unexpectedly large ranges
            hosts = hosts[:1024]
        if not hosts:
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            list(pool.map(lambda h: self._ping_once(str(h), timeout_s), hosts))

    def _read_system_arp_cache(self) -> dict:
        """
        Purpose:
            Parse the OS's own ARP/neighbor table into ip -> mac pairs.
            Reading this table is a plain, unprivileged operation on
            every major OS (unlike opening a raw socket for scapy's
            srp()), which is what makes the fallback scan work without
            admin/root.
        Parameters:
            None
        Returns:
            dict: {ip: normalized_mac, ...}
        """
        system = platform.system()
        pairs = {}
        try:
            if system == "Windows":
                out = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                        ip, mac = parts[0], parts[1]
                        if is_valid_mac(mac.replace("-", ":")):
                            pairs[ip] = normalize_mac(mac)
            elif system == "Linux":
                try:
                    out = subprocess.check_output(["ip", "neigh", "show"], text=True, errors="ignore")
                    for line in out.splitlines():
                        parts = line.split()
                        if (len(parts) >= 5 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0])
                                and "lladdr" in parts):
                            ip = parts[0]
                            mac = parts[parts.index("lladdr") + 1]
                            pairs[ip] = normalize_mac(mac)
                except (OSError, subprocess.SubprocessError):
                    out = subprocess.check_output(["arp", "-n"], text=True, errors="ignore")
                    for line in out.splitlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                            ip, mac = parts[0], parts[2]
                            if is_valid_mac(mac):
                                pairs[ip] = normalize_mac(mac)
            else:  # Darwin / other BSD-likes
                out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
                for line in out.splitlines():
                    m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9A-Fa-f:]{11,17})", line)
                    if m:
                        pairs[m.group(1)] = normalize_mac(m.group(2))
        except Exception as exc:
            app_logger.warning(f"Could not read the system ARP cache: {exc}", source="scanner")
        return pairs

    def arp_scan_fallback(self, cidr: str, timeout: int = 3):
        """
        Purpose:
            No-privilege device discovery: ping-sweep the subnet so every
            live host lands in the OS's ARP/neighbor cache, then read that
            cache back and filter it down to the target range. This is
            the path used automatically whenever the raw-socket scapy
            sweep isn't available (not installed, or not running
            elevated) - the most common situation on a typical student
            laptop.
        Parameters:
            cidr (str): network range to scan, e.g. "192.168.1.0/24".
            timeout (int): rough per-host timeout budget (seconds).
        Returns:
            list[dict]: one dict per discovered device, same shape as
                        arp_scan() ('ip', 'mac', 'vendor', 'hostname',
                        'last_seen').
        """
        if not cidr:
            return []
        self._ping_sweep(cidr, timeout_s=min(max(timeout, 1), 2))
        cache = self._read_system_arp_cache()

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            network = None

        devices = []
        for ip, mac in cache.items():
            if network is not None:
                try:
                    if ipaddress.ip_address(ip) not in network:
                        continue
                except ValueError:
                    continue
            if not is_valid_mac(mac) or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                continue
            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": lookup_vendor(mac),
                "hostname": self.resolve_hostname(ip),
                "last_seen": now_iso(),
            })
        return devices

    def get_gateway_mac(self, gateway_ip: str, cidr: str, timeout: int = 3) -> str:
        """
        Purpose:
            Determine the gateway's MAC address, which detector.py uses as
            the ground truth to detect "fake gateway" / default-route
            spoofing attacks.
        Parameters:
            gateway_ip (str): the gateway's IP address.
            cidr (str): the local network range (used only if a full scan
                        is needed as a fallback).
            timeout (int): seconds to wait for a reply.
        Returns:
            str: normalized MAC address of the gateway, or "" if unknown.
        Workflow:
            1. Send a single targeted ARP request to the gateway IP (only
               attempted if scapy is available).
            2. Fall back to arp_scan() (which itself tries scapy, then
               the no-privilege ping+ARP-cache method) and filter for the
               gateway IP if the direct request didn't get a reply - this
               means the gateway MAC still resolves even without scapy or
               elevated privileges.
        """
        if not gateway_ip:
            return ""
        if SCAPY_AVAILABLE:
            try:
                request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
                answered, _ = srp(request, timeout=timeout, verbose=False)
                for _sent, received in answered:
                    if received.psrc == gateway_ip:
                        return normalize_mac(received.hwsrc)
            except Exception as exc:
                app_logger.warning(f"Direct gateway ARP query failed: {exc}", source="scanner")

        for device in self.arp_scan(cidr, timeout=timeout):
            if device["ip"] == gateway_ip:
                return device["mac"]
        return ""
