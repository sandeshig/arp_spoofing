"""
graph.py
========
Matplotlib chart builders. Every function returns a matplotlib Figure
object (it does NOT call plt.show()), so the caller can either:

  - embed it in the Tkinter GUI via FigureCanvasTkAgg (Graphs tab), or
  - save it to disk with fig.savefig(path) for inclusion in PDF reports.

Keeping this module Figure-in / Figure-out (no GUI or file-system side
effects baked in) keeps it reusable and easy to test.
"""

import matplotlib
matplotlib.use("Agg")  # safe default backend; the GUI swaps this for TkAgg on embed
import matplotlib.pyplot as plt

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

DARK_BG = "#1e1e2e"
DARK_FG = "#e0e0e0"
ACCENT_COLORS = ["#e74c3c", "#f1c40f", "#3498db", "#2ecc71", "#9b59b6", "#1abc9c", "#e67e22"]


def _style_dark(fig, ax):
    """
    Purpose:
        Apply the app's dark cybersecurity theme consistently to any chart.
    Parameters:
        fig: matplotlib Figure.
        ax: matplotlib Axes (or an iterable of Axes).
    Returns:
        None
    """
    fig.patch.set_facecolor(DARK_BG)
    axes = ax if hasattr(ax, "__iter__") else [ax]
    for a in axes:
        a.set_facecolor(DARK_BG)
        a.tick_params(colors=DARK_FG)
        a.xaxis.label.set_color(DARK_FG)
        a.yaxis.label.set_color(DARK_FG)
        a.title.set_color(DARK_FG)
        for spine in a.spines.values():
            spine.set_color("#3a3a4a")


def build_alert_severity_pie(severity_counts: dict):
    """
    Purpose:
        Pie chart of alerts by severity (info / warning / critical), for
        a quick "how bad is it" snapshot on the Graphs tab and reports.
    Parameters:
        severity_counts (dict): e.g. {'info': 4, 'warning': 9, 'critical': 2}.
    Returns:
        matplotlib.figure.Figure
    """
    labels = [k for k, v in severity_counts.items() if v > 0]
    sizes = [v for v in severity_counts.values() if v > 0]
    colors_map = {"info": "#2ecc71", "warning": "#f1c40f", "critical": "#e74c3c"}
    colors = [colors_map.get(l, "#3498db") for l in labels]

    fig, ax = plt.subplots(figsize=(5, 4))
    if sizes:
        ax.pie(sizes, labels=labels, colors=colors, autopct="%1.0f%%",
               textprops={"color": DARK_FG, "fontsize": 10})
    else:
        ax.text(0.5, 0.5, "No alerts yet", ha="center", va="center", color=DARK_FG)
    ax.set_title("Alerts by Severity")
    _style_dark(fig, ax)
    fig.tight_layout()
    return fig


def build_category_bar_chart(category_counts):
    """
    Purpose:
        Bar chart of alert counts grouped by detection category
        (MAC_CHANGE, FAKE_GATEWAY, etc.) - the "Threat Frequency" chart.
    Parameters:
        category_counts (list[dict] | list[sqlite3.Row]): rows with
            'category' and 'c' (count) keys/columns.
    Returns:
        matplotlib.figure.Figure
    """
    categories = [row["category"] for row in category_counts]
    counts = [row["c"] for row in category_counts]

    fig, ax = plt.subplots(figsize=(6, 4))
    if categories:
        bars = ax.bar(categories, counts, color=ACCENT_COLORS[:len(categories)])
        ax.bar_label(bars, color=DARK_FG, fontsize=8)
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right", fontsize=8)
    else:
        ax.text(0.5, 0.5, "No alerts yet", ha="center", va="center", color=DARK_FG)
    ax.set_title("Threat Frequency by Category")
    ax.set_ylabel("Alert Count")
    _style_dark(fig, ax)
    fig.tight_layout()
    return fig


def build_device_count_chart(online_count: int, offline_count: int, unauthorized_count: int):
    """
    Purpose:
        Simple bar chart summarizing the current device population, for
        the "Network Device Count" panel.
    Parameters:
        online_count (int): number of devices currently online.
        offline_count (int): number of devices currently offline.
        unauthorized_count (int): number of unauthorized/unknown devices.
    Returns:
        matplotlib.figure.Figure
    """
    labels = ["Online", "Offline", "Unauthorized"]
    values = [online_count, offline_count, unauthorized_count]
    colors = ["#2ecc71", "#7f8c8d", "#e74c3c"]

    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(labels, values, color=colors)
    ax.bar_label(bars, color=DARK_FG)
    ax.set_title("Network Device Count")
    ax.set_ylabel("Devices")
    _style_dark(fig, ax)
    fig.tight_layout()
    return fig


def build_attack_timeline(alert_rows):
    """
    Purpose:
        Scatter/line timeline of alerts over time, colored by severity, so
        an analyst can visually spot bursts of activity (the "Attack
        Timeline" chart).
    Parameters:
        alert_rows (list[dict] | list[sqlite3.Row]): rows with
            'timestamp' and 'severity' keys/columns, in chronological order.
    Returns:
        matplotlib.figure.Figure
    """
    color_map = {"info": "#2ecc71", "warning": "#f1c40f", "critical": "#e74c3c"}
    fig, ax = plt.subplots(figsize=(8, 4))

    if alert_rows:
        xs = list(range(len(alert_rows)))
        colors = [color_map.get(row["severity"], "#3498db") for row in alert_rows]
        ax.scatter(xs, [1] * len(xs), c=colors, s=40)
        # Show a readable subset of timestamps on the x-axis so labels don't overlap.
        step = max(1, len(alert_rows) // 10)
        tick_positions = xs[::step]
        tick_labels = [alert_rows[i]["timestamp"][11:19] for i in tick_positions]
        ax.set_xticks(tick_positions)
        ax.set_xticklabels(tick_labels, rotation=45, ha="right", fontsize=8)
        ax.set_yticks([])
    else:
        ax.text(0.5, 0.5, "No alerts recorded yet", ha="center", va="center", color=DARK_FG)

    ax.set_title("Attack / Alert Timeline")
    _style_dark(fig, ax)
    fig.tight_layout()
    return fig


def build_statistics_trend(stat_rows):
    """
    Purpose:
        Line chart of packets captured and alert totals over the
        monitoring session, from periodic statistics snapshots.
    Parameters:
        stat_rows (list[dict] | list[sqlite3.Row]): rows with
            'timestamp', 'packets_captured', 'alerts_total' columns,
            chronologically ordered (oldest first).
    Returns:
        matplotlib.figure.Figure
    """
    fig, ax = plt.subplots(figsize=(8, 4))
    if stat_rows:
        xs = list(range(len(stat_rows)))
        packets = [row["packets_captured"] for row in stat_rows]
        alerts = [row["alerts_total"] for row in stat_rows]
        ax.plot(xs, packets, color="#3498db", label="Packets Captured", linewidth=2)
        ax.plot(xs, alerts, color="#e74c3c", label="Alerts Raised", linewidth=2)
        ax.legend(facecolor=DARK_BG, labelcolor=DARK_FG)
    else:
        ax.text(0.5, 0.5, "No statistics recorded yet", ha="center", va="center", color=DARK_FG)
    ax.set_title("Session Trend")
    _style_dark(fig, ax)
    fig.tight_layout()
    return fig


def build_network_topology(host_ip: str, gateway_ip: str, devices):
    """
    Purpose:
        Draw a node-graph of the LAN: this host, the gateway/router, and
        every other discovered device, connected as spokes off the
        gateway. Unauthorized/unknown devices are highlighted in red so a
        suspicious node stands out visually - this is the "Network
        Topology" panel from the project spec (PC / Gateway / Router /
        Connected Devices / Unknown Devices, suspicious nodes highlighted).
    Parameters:
        host_ip (str): this machine's IP address (drawn as "PC").
        gateway_ip (str): the LAN gateway/router IP address.
        devices (list[dict] | list[sqlite3.Row]): rows with 'ip' and
            'authorized' keys/columns (as returned by database.get_all_devices()).
    Returns:
        matplotlib.figure.Figure
    Workflow:
        1. Build an undirected graph: gateway at the center, every other
           IP (host + discovered devices) connected to it by one edge.
        2. Color nodes by role: gateway (blue), this PC (green),
           authorized device (yellow), unauthorized/unknown device (red).
        3. Lay it out with a spring layout so it reads as a simple
           hub-and-spoke network diagram.
    """
    fig, ax = plt.subplots(figsize=(7, 6))

    if not NETWORKX_AVAILABLE:
        ax.text(0.5, 0.5, "networkx is not installed", ha="center", va="center", color=DARK_FG)
        ax.set_title("Network Topology")
        _style_dark(fig, ax)
        return fig

    graph_obj = nx.Graph()
    gw_label = gateway_ip or "Gateway"
    host_label = host_ip or "This PC"
    graph_obj.add_node(gw_label, kind="gateway")
    if host_label != gw_label:
        graph_obj.add_node(host_label, kind="host")
        graph_obj.add_edge(gw_label, host_label)

    seen_ips = {gw_label, host_label}
    for d in devices:
        ip = d["ip"] if not isinstance(d, dict) else d.get("ip")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        authorized = bool(d["authorized"]) if not isinstance(d, dict) else bool(d.get("authorized"))
        graph_obj.add_node(ip, kind="device", authorized=authorized)
        graph_obj.add_edge(gw_label, ip)

    color_map = []
    for node, data in graph_obj.nodes(data=True):
        kind = data.get("kind")
        if kind == "gateway":
            color_map.append("#3498db")   # blue - router/gateway
        elif kind == "host":
            color_map.append("#2ecc71")   # green - this PC
        elif data.get("authorized"):
            color_map.append("#f1c40f")   # yellow - known/authorized device
        else:
            color_map.append("#e74c3c")   # red - unknown/suspicious device

    pos = nx.spring_layout(graph_obj, seed=42, k=0.9)
    nx.draw(
        graph_obj, pos, ax=ax, with_labels=True, node_color=color_map,
        node_size=900, font_size=7, font_color="#1c1c1c", font_weight="bold",
        edge_color="#4a4a5a", linewidths=1, edgecolors="#0f0f18",
    )
    ax.set_title("Network Topology (blue=gateway, green=this PC, yellow=known, red=unauthorized)",
                  fontsize=9)
    _style_dark(fig, ax)
    fig.tight_layout()
    return fig


def save_figure(fig, path: str) -> str:
    """
    Purpose:
        Save a Figure to disk as a PNG (used when embedding charts into
        PDF reports via exporter.py).
    Parameters:
        fig: matplotlib Figure.
        path (str): destination file path (should end in .png).
    Returns:
        str: the path the figure was saved to.
    """
    fig.savefig(path, facecolor=fig.get_facecolor(), dpi=150, bbox_inches="tight")
    return path
