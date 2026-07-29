"""
demo_simulator.py
==================
A safe way to demonstrate ArpDetector's live detection logic for a
presentation/viva without needing a second attacking machine and without
sending a single real packet on the network.

Every "attack" here is a scapy Ether()/ARP() packet object built entirely
in memory and handed directly to detector.ArpDetector._on_packet() - the
exact same analysis code real sniffed traffic goes through. Nothing in
this file ever touches a socket, ever calls sniff()/srp()/send(), or ever
requires raw-socket privileges. It cannot affect, scan, or spoof any real
device - it only exercises your own detector's decision logic with
scripted data.

Use this from the Dashboard's "Run Demo Scenario" button, or standalone:

    python demo_simulator.py
"""

import time

from utils import normalize_mac

try:
    from scapy.all import Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _build_arp_packet(sender_ip, sender_mac, target_ip, target_mac="00:00:00:00:00:00", op=2):
    """
    Purpose:
        Construct an ARP packet purely as an in-memory Python object - it
        is never written to a socket or interface.
    Parameters:
        sender_ip (str): the ARP 'psrc' field (who is talking).
        sender_mac (str): the ARP 'hwsrc' field.
        target_ip (str): the ARP 'pdst' field (who they're talking to/about).
        target_mac (str): the ARP 'hwdst' field.
        op (int): 1 = ARP request ("who-has"), 2 = ARP reply ("is-at").
    Returns:
        scapy Ether/ARP packet object.
    """
    return Ether(src=sender_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=op, psrc=sender_ip, hwsrc=sender_mac, pdst=target_ip, hwdst=target_mac
    )


def run_demo_scenario(detector_instance, delay: float = 1.0, stop_event=None) -> None:
    """
    Purpose:
        Feed a scripted sequence of synthetic ARP events into a real
        ArpDetector instance so every detection rule fires at least once,
        driving the full GUI (popups, sound, Live Monitor table, Alerts
        table, Dashboard counters, Graphs) exactly as a live attack would.
    Parameters:
        detector_instance (detector.ArpDetector): a detector instance
            already configured with alert_callback / packet_callback /
            stats_callback (main.py builds one this way). Its .start()
            does NOT need to have been called - this function never uses
            the detector's sniff thread, only its packet-analysis method.
        delay (float): seconds to pause between simulated events, so a
            live audience can follow along instead of it flashing by.
        stop_event (threading.Event | None): if provided, allows a caller
            to cancel a running demo early (checked between each step).
    Returns:
        None
    Workflow (escalating scenario, mirrors a real incident's shape):
        1. Baseline: two already-established devices talking normally.
        2. A brand-new device joins the network (UNKNOWN_DEVICE alert).
        3. That device's IP is suddenly claimed by a different MAC
           (MAC_CHANGE alert - the classic ARP-spoofing signature).
        4. A device impersonates the gateway (FAKE_GATEWAY alert - MITM).
        5. A burst of gratuitous ARP announcements from the attacker MAC
           (GRATUITOUS_FLOOD alert - cache-poisoning technique).
        6. A rapid burst of replies from many source IPs (BROADCAST_STORM alert).
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required to build demo packets. Install it with: pip install scapy")

    def _pause() -> bool:
        """Sleep for `delay` seconds, honoring an optional cancellation event."""
        if stop_event is not None:
            return stop_event.wait(delay)
        time.sleep(delay)
        return False

    gateway_ip = detector_instance.gateway_ip or "192.168.1.1"
    gateway_mac = detector_instance.gateway_mac or normalize_mac("AA:BB:CC:00:00:01")

    # Write these back onto the detector itself. If the real network
    # detection never resolved a gateway (common on a laptop where the
    # active scan needs admin/root, or scapy fell back to a no-privilege
    # path), detector_instance.gateway_ip/gateway_mac can be "" - and
    # _check_fake_gateway() bails out immediately whenever gateway_ip is
    # falsy. That would silently drop the whole FAKE_GATEWAY step (the
    # scenario's only CRITICAL source besides the broadcast storm), so the
    # demo must guarantee the detector actually has gateway context to
    # compare against, independent of whatever real-network detection did.
    detector_instance.gateway_ip = gateway_ip
    detector_instance.gateway_mac = gateway_mac

    known_ip = "192.168.1.50"
    known_mac = normalize_mac("AA:BB:CC:00:00:50")
    attacker_mac = normalize_mac("DE:AD:BE:EF:00:66")

    # Pre-seed the "already on the network" devices as trusted, exactly as a
    # real initial ARP scan would (main.py does this via seed_trusted_map()
    # before starting live capture) - this keeps step 1 genuinely silent, so
    # the story reads as baseline -> new device -> spoofing -> MITM -> flood
    # -> storm instead of everything alerting as "new" all at once.
    detector_instance.seed_trusted_map([(known_ip, known_mac), (gateway_ip, gateway_mac)])

    # 1. Normal baseline traffic between two already-known devices - no alert expected.
    detector_instance._on_packet(_build_arp_packet(known_ip, known_mac, gateway_ip))
    detector_instance._on_packet(_build_arp_packet(gateway_ip, gateway_mac, known_ip))
    if _pause():
        return

    # 2. A new device joins the network.
    new_ip, new_mac = "192.168.1.77", normalize_mac("11:22:33:44:55:66")
    detector_instance._on_packet(_build_arp_packet(new_ip, new_mac, gateway_ip))
    if _pause():
        return

    # 3. MAC change on a known IP - the classic ARP-spoofing signature.
    detector_instance._on_packet(_build_arp_packet(known_ip, attacker_mac, gateway_ip))
    if _pause():
        return

    # 4. Fake gateway impersonation - a Man-in-the-Middle setup.
    detector_instance._on_packet(_build_arp_packet(gateway_ip, attacker_mac, known_ip))
    if _pause():
        return

    # 5. Burst of gratuitous ARP announcements (psrc == pdst) from the
    #    attacker. The detector's flood check only looks at a rolling
    #    1-second window, so this burst is paced on its own short fixed
    #    interval (independent of the caller's `delay`) - otherwise a
    #    delay of 1s+ (used for readability elsewhere in this scenario)
    #    would space the packets out enough that the window never
    #    accumulates past the threshold, and this WARNING/"medium" alert
    #    would silently never fire.
    burst_pause = min(delay, 0.12) if delay else 0.12
    for _ in range(8):
        detector_instance._on_packet(_build_arp_packet(gateway_ip, attacker_mac, gateway_ip))
        if stop_event is not None:
            if stop_event.wait(burst_pause):
                return
        else:
            time.sleep(burst_pause)

    # 6. Broadcast storm: a rapid burst of replies from many distinct source IPs.
    #    Pre-seed these as trusted too, so the demo highlights the storm itself
    #    rather than 35 unrelated "new device" alerts.
    storm_pairs = [
        (f"192.168.1.{100 + (i % 50)}", normalize_mac(f"AA:CC:EE:00:00:{i:02X}"))
        for i in range(35)
    ]
    detector_instance.seed_trusted_map(storm_pairs)
    for fake_ip, fake_mac in storm_pairs:
        detector_instance._on_packet(_build_arp_packet(fake_ip, fake_mac, gateway_ip))


if __name__ == "__main__":
    # Standalone console demo - prints alerts as they fire, no GUI needed.
    from settings import settings
    from detector import ArpDetector

    def _print_alert(alert):
        print(f"[{alert['timestamp']}] {alert['severity'].upper():<9} {alert['category']:<18} {alert['message']}")

    print("Running ARP Monitor demo scenario (synthetic packets only - nothing sent on the network)...\n")
    demo_detector = ArpDetector(
        settings_obj=settings, interface="demo0", gateway_ip="192.168.1.1",
        gateway_mac="AA:BB:CC:00:00:01", alert_callback=_print_alert,
    )
    run_demo_scenario(demo_detector, delay=0.5)
    print("\nDemo complete.")
