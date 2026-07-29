"""
notifier.py
===========
Everything related to getting an alert in front of the user:

  - a themed Tkinter popup window (blocking-free, non-modal)
  - an OS sound alert (winsound on Windows, terminal bell elsewhere)
  - an OS-level desktop notification via `plyer` (best-effort, optional)
  - a blinking-indicator helper the GUI polls to flash the alert icon

Every function here is best-effort and defensively wrapped: a failure to
play a sound or show a desktop toast must never crash the detection
pipeline, so all of them catch and log exceptions instead of raising.
"""

import platform
import threading
import time

from settings import settings
from logger import app_logger

try:
    import tkinter as tk
    TK_AVAILABLE = True
except ImportError:
    TK_AVAILABLE = False

try:
    from plyer import notification as plyer_notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

if platform.system() == "Windows":
    try:
        import winsound
        WINSOUND_AVAILABLE = True
    except ImportError:
        WINSOUND_AVAILABLE = False
else:
    WINSOUND_AVAILABLE = False


SEVERITY_COLORS = {
    "info": "#2ecc71",       # green
    "warning": "#f1c40f",    # yellow
    "critical": "#e74c3c",   # red
}


class BlinkState:
    """
    Purpose:
        Tiny shared flag the dashboard polls to flash an "ALERT" indicator
        after a critical event, without the GUI needing to know anything
        about how/why the flag was set.
    """

    def __init__(self):
        self.active = False
        self._until = 0.0
        self._lock = threading.Lock()

    def trigger(self, duration_seconds: float = 8.0) -> None:
        """
        Purpose:
            Turn the blink indicator on for a fixed duration.
        Parameters:
            duration_seconds (float): how long the indicator should stay active.
        Returns:
            None
        """
        with self._lock:
            self.active = True
            self._until = time.time() + duration_seconds

    def is_active(self) -> bool:
        """
        Purpose:
            Check (and auto-expire) the blink indicator state; called on a
            GUI timer tick, typically every 500ms, to toggle an icon.
        Parameters:
            None
        Returns:
            bool: True while within the trigger() duration window.
        """
        with self._lock:
            if self.active and time.time() > self._until:
                self.active = False
            return self.active


blink_state = BlinkState()


def play_alert_sound(severity: str = "warning") -> None:
    """
    Purpose:
        Play a short OS sound appropriate to the alert severity.
    Parameters:
        severity (str): 'info' | 'warning' | 'critical'.
    Returns:
        None
    Workflow:
        - Respects the user's "alert_sound" setting.
        - Windows: uses winsound with a built-in system sound alias.
        - Other platforms: falls back to the terminal bell character,
          which is audible in most terminal emulators without needing
          any extra audio library.
    """
    if not settings.get("alert_sound", True):
        return
    try:
        if WINSOUND_AVAILABLE:
            alias = "SystemHand" if severity == "critical" else "SystemExclamation"
            winsound.PlaySound(alias, winsound.SND_ALIAS | winsound.SND_ASYNC)
        else:
            print("\a", end="", flush=True)
    except Exception as exc:
        app_logger.warning(f"Could not play alert sound: {exc}", source="notifier")


def show_desktop_notification(title: str, message: str) -> None:
    """
    Purpose:
        Show an OS-level desktop toast notification (outside the app
        window) so alerts are visible even if the app is minimized.
    Parameters:
        title (str): notification title.
        message (str): notification body text.
    Returns:
        None
    Workflow:
        Uses `plyer`, a cross-platform notification library, if it is
        installed; otherwise this is a silent no-op (the in-app popup and
        Alerts tab remain the guaranteed notification path).
    """
    if not settings.get("desktop_notifications", True):
        return
    if not PLYER_AVAILABLE:
        return
    try:
        plyer_notification.notify(title=title, message=message, timeout=6)
    except Exception as exc:
        app_logger.warning(f"Desktop notification failed: {exc}", source="notifier")


def show_alert_popup(root, alert: dict) -> None:
    """
    Purpose:
        Show a small, non-blocking, color-coded Toplevel popup window for
        a new alert, auto-closing after a few seconds.
    Parameters:
        root: the Tkinter root/Tk instance to parent the popup to (popups
              created without a running mainloop are a no-op).
        alert (dict): alert data with 'severity', 'category', 'message' keys.
    Returns:
        None
    Workflow:
        1. Bail out quietly if Tkinter isn't available or root is None.
        2. Build a small borderless-ish Toplevel in the bottom-right corner.
        3. Color it according to severity.
        4. Auto-destroy it after a timeout (longer for critical alerts).
        This function must always be called from the main GUI thread
        (Tkinter is not thread-safe) - background threads should hand the
        alert to the GUI via a thread-safe queue and let the GUI's own
        polling loop call this function.
    """
    if not TK_AVAILABLE or root is None:
        return
    try:
        severity = alert.get("severity", "info")
        color = SEVERITY_COLORS.get(severity, "#3498db")
        duration_ms = 10000 if severity == "critical" else 6000

        popup = tk.Toplevel(root)
        popup.overrideredirect(True)
        popup.attributes("-topmost", True)
        popup.configure(bg=color)

        screen_w = popup.winfo_screenwidth()
        screen_h = popup.winfo_screenheight()
        width, height = 360, 110
        x = screen_w - width - 20
        y = screen_h - height - 60
        popup.geometry(f"{width}x{height}+{x}+{y}")

        header = tk.Label(
            popup, text=f"⚠ {alert.get('category', 'ALERT')}",
            bg=color, fg="#1c1c1c", font=("Segoe UI", 11, "bold"), anchor="w",
        )
        header.pack(fill="x", padx=10, pady=(8, 0))

        body = tk.Label(
            popup, text=alert.get("message", ""), bg=color, fg="#1c1c1c",
            font=("Segoe UI", 9), wraplength=340, justify="left", anchor="w",
        )
        body.pack(fill="both", expand=True, padx=10, pady=(2, 8))

        popup.bind("<Button-1>", lambda e: popup.destroy())
        popup.after(duration_ms, popup.destroy)

        if severity == "critical":
            blink_state.trigger()
            play_alert_sound(severity)
            show_desktop_notification(f"ARP Monitor: {alert.get('category', 'Alert')}", alert.get("message", ""))
        elif severity == "warning":
            play_alert_sound(severity)
    except Exception as exc:
        app_logger.warning(f"Failed to show alert popup: {exc}", source="notifier")
