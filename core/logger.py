"""
=============================================================
  IntelliGuard - Logging & Alert System
  File: core/logger.py
  Description: Handles structured logging of all events,
               alert generation, and log display formatting.
               Uses color-coded console output for clarity.
  Made By Monish Paramasivam
=============================================================
"""

import os
import csv
import json
from datetime import datetime
from collections import Counter


# ── ANSI Color Codes ──────────────────────────────────────────────────────────
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

    @staticmethod
    def red(s):    return f"{Colors.RED}{s}{Colors.RESET}"
    @staticmethod
    def yellow(s): return f"{Colors.YELLOW}{s}{Colors.RESET}"
    @staticmethod
    def green(s):  return f"{Colors.GREEN}{s}{Colors.RESET}"
    @staticmethod
    def cyan(s):   return f"{Colors.CYAN}{s}{Colors.RESET}"
    @staticmethod
    def bold(s):   return f"{Colors.BOLD}{s}{Colors.RESET}"
    @staticmethod
    def dim(s):    return f"{Colors.DIM}{s}{Colors.RESET}"


def load_config(config_path="config.json"):
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.join(base, config_path)
    with open(full_path, "r") as f:
        return json.load(f)


LOG_FIELDS = [
    "timestamp", "ip_address", "event_type", "endpoint",
    "request_rate", "failed_logins", "session_duration",
    "unique_endpoints", "bytes_transferred", "login_attempts", "hour_of_day",
    "label", "severity", "raw_score", "reasons"
]


class EventLogger:
    """
    Handles structured logging of network events to CSV and console.
    Provides alert formatting and log display utilities.
    """

    def __init__(self):
        self.config   = load_config()
        self.log_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            self.config["logging"]["log_file"]
        )
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        self._init_log_file()

    def _init_log_file(self):
        """Create log file with header if it doesn't exist."""
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
                writer.writeheader()

    def log_event(self, event: dict, result: dict) -> dict:
        """
        Log a single processed event to file and return the log record.

        Args:
            event:  Raw event dictionary from simulator.
            result: Detection result from AnomalyDetector.predict().

        Returns:
            Combined log record dictionary.
        """
        record = {
            "timestamp":        event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "ip_address":       event.get("ip_address", "0.0.0.0"),
            "event_type":       event.get("event_type", "UNKNOWN"),
            "endpoint":         event.get("endpoint", "/"),
            "request_rate":     event.get("request_rate", 0),
            "failed_logins":    event.get("failed_logins", 0),
            "session_duration": event.get("session_duration", 0),
            "unique_endpoints": event.get("unique_endpoints", 0),
            "bytes_transferred":event.get("bytes_transferred", 0),
            "login_attempts":   event.get("login_attempts", 0),
            "hour_of_day":      event.get("hour_of_day", 12),
            "label":            result.get("label", "NORMAL"),
            "severity":         result.get("severity", "NORMAL"),
            "raw_score":        result.get("raw_score", 0.0),
            "reasons":          " | ".join(result.get("reason", [])),
        }

        with open(self.log_file, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
            writer.writerow(record)

        return record

    def log_events_batch(self, events: list, results: list) -> list:
        """
        Log a batch of events.

        Args:
            events:  List of raw event dicts.
            results: List of detection result dicts.

        Returns:
            List of log records.
        """
        records = []
        for event, result in zip(events, results):
            records.append(self.log_event(event, result))
        return records

    # ── Alert Display ─────────────────────────────────────────────────────────

    def print_alert(self, record: dict) -> None:
        """
        Print a formatted alert for a suspicious event.
        Uses color coding by severity.
        """
        severity = record.get("severity", "LOW")
        sep_char = "═" if severity == "HIGH" else "─"
        width    = 70

        # Color by severity
        if severity == "HIGH":
            color     = Colors.RED
            icon      = "🚨"
            sev_label = Colors.red(f"[{severity} ALERT]")
        elif severity == "MEDIUM":
            color     = Colors.YELLOW
            icon      = "⚠️ "
            sev_label = Colors.yellow(f"[{severity} ALERT]")
        else:
            color     = Colors.CYAN
            icon      = "ℹ️ "
            sev_label = Colors.cyan(f"[{severity} ALERT]")

        print(f"\n  {color}{sep_char * width}{Colors.RESET}")
        print(f"  {icon}  {sev_label}  {Colors.bold(record['timestamp'])}")
        print(f"  {color}{sep_char * width}{Colors.RESET}")
        print(f"  {Colors.bold('IP Address')}    : {Colors.yellow(record['ip_address'])}")
        print(f"  {Colors.bold('Event Type')}    : {record.get('event_type', 'UNKNOWN')}")
        print(f"  {Colors.bold('Endpoint')}      : {record.get('endpoint', '/')}")
        print(f"  {Colors.bold('Request Rate')}  : {record.get('request_rate', 0):.1f} req/min")
        print(f"  {Colors.bold('Failed Logins')} : {record.get('failed_logins', 0)}")
        print(f"  {Colors.bold('Login Attempts')}: {record.get('login_attempts', 0)}")
        print(f"  {Colors.bold('Anomaly Score')} : {record.get('raw_score', 0):.4f}")

        reasons = record.get("reasons", "")
        if reasons:
            print(f"\n  {Colors.bold('DETECTION REASONS:')}")
            for r in reasons.split(" | "):
                if r.strip():
                    print(f"    {Colors.red('►')} {r.strip()}")

        print(f"  {color}{sep_char * width}{Colors.RESET}")

    def print_normal(self, record: dict) -> None:
        """Print a brief normal event notification."""
        print(
            f"  {Colors.green('✓')} {record['timestamp']} | "
            f"IP: {record['ip_address']:<18}| "
            f"Score: {record['raw_score']:>7.4f} | "
            f"{Colors.green('NORMAL')}"
        )

    # ── Log Viewer ────────────────────────────────────────────────────────────

    def view_logs(self, n: int = None) -> None:
        """
        Display recent logs in a formatted table.

        Args:
            n: Number of recent entries to display. Defaults to config value.
        """
        if n is None:
            n = self.config["logging"]["max_display_rows"]

        if not os.path.exists(self.log_file):
            print(Colors.yellow("  [!] No logs found. Run a simulation first."))
            return

        rows = []
        with open(self.log_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)

        if not rows:
            print(Colors.yellow("  [!] Log file is empty."))
            return

        recent = rows[-n:]

        # Header
        print(f"\n  {Colors.bold('IntelliGuard Event Log')} — showing last {len(recent)} of {len(rows)} entries")
        print("  " + "─" * 110)
        header = (
            f"  {'#':<5} {'Timestamp':<22} {'IP Address':<18} "
            f"{'Type':<18} {'Rate':>7} {'Fails':>6} {'Score':>8} {'Severity':<10} {'Label'}"
        )
        print(Colors.bold(header))
        print("  " + "─" * 110)

        for i, row in enumerate(recent, 1):
            label    = row.get("label", "NORMAL")
            severity = row.get("severity", "NORMAL")

            label_colored = Colors.red(f"{label:<12}") if label == "SUSPICIOUS" else Colors.green(f"{label:<12}")

            sev_colored = {
                "HIGH":   Colors.red(f"{severity:<10}"),
                "MEDIUM": Colors.yellow(f"{severity:<10}"),
                "LOW":    Colors.cyan(f"{severity:<10}"),
            }.get(severity, Colors.green(f"{severity:<10}"))

            print(
                f"  {i:<5} {row.get('timestamp',''):<22} {row.get('ip_address',''):<18} "
                f"{row.get('event_type',''):<18} {float(row.get('request_rate',0)):>7.1f} "
                f"{row.get('failed_logins','0'):>6} {float(row.get('raw_score',0)):>8.4f} "
                f"{sev_colored} {label_colored}"
            )

        print("  " + "─" * 110)

        # Summary
        labels    = [r.get("label", "NORMAL") for r in rows]
        sevs      = [r.get("severity", "NORMAL") for r in rows]
        sus_count = labels.count("SUSPICIOUS")
        nor_count = labels.count("NORMAL")

        print(f"\n  {Colors.bold('Summary')}:")
        print(f"    Total Events : {len(rows)}")
        print(f"    Normal       : {Colors.green(str(nor_count))}")
        print(f"    Suspicious   : {Colors.red(str(sus_count))}")
        print(f"    High Alerts  : {Colors.red(str(sevs.count('HIGH')))}")
        print(f"    Med  Alerts  : {Colors.yellow(str(sevs.count('MEDIUM')))}")
        print(f"    Low  Alerts  : {Colors.cyan(str(sevs.count('LOW')))}")
        print()

    def clear_logs(self) -> None:
        """Clear all logs (reinitialize log file)."""
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        self._init_log_file()
        print(Colors.yellow("  [✓] Logs cleared."))

    def get_stats(self) -> dict:
        """Return summary statistics from log file."""
        if not os.path.exists(self.log_file):
            return {}
        rows = []
        with open(self.log_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
        if not rows:
            return {}
        labels = [r.get("label", "NORMAL") for r in rows]
        return {
            "total":      len(rows),
            "normal":     labels.count("NORMAL"),
            "suspicious": labels.count("SUSPICIOUS"),
            "high":       sum(1 for r in rows if r.get("severity") == "HIGH"),
            "medium":     sum(1 for r in rows if r.get("severity") == "MEDIUM"),
            "low":        sum(1 for r in rows if r.get("severity") == "LOW"),
        }
