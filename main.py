"""
=============================================================
  IntelliGuard: AI Intrusion Detection System
  File: main.py  (CLI Dashboard - Entry Point)
  Made By Monish Paramasivam
=============================================================
"""

import os
import sys
import time

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.detector  import DetectionPipeline
from core.simulator import (
    stream_normal_traffic,
    stream_attack_traffic,
    simulate_normal_event,
    simulate_brute_force_event,
    simulate_rapid_request_event,
    simulate_scan_event,
)
from core.logger  import EventLogger, Colors
from core.ml_engine import visualize_scores


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ██╗███╗   ██╗████████╗███████╗██╗     ██╗     ██╗                ║
║    ██║████╗  ██║╚══██╔══╝██╔════╝██║     ██║    ██╔╝                ║
║    ██║██╔██╗ ██║   ██║   █████╗  ██║     ██║   ██╔╝                 ║
║    ██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██║  ██╔╝                  ║
║    ██║██║ ╚████║   ██║   ███████╗███████╗██║ ██╔╝                   ║
║    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝╚═╝                    ║
║                                                                      ║
║   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗                         ║
║  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗                        ║
║  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║                        ║
║  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║                        ║
║  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝                        ║
║   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                        ║
║                                                                      ║
║         AI-POWERED INTRUSION DETECTION SYSTEM  v1.0.0               ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  Made By: Monish Paramasivam         Powered by: Isolation Forest   ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""

MENU = f"""
{Colors.BOLD}  ┌─────────────────────────────────────────────────────┐
  │               INTELLIGUARD MAIN MENU                │
  ├─────────────────────────────────────────────────────┤
  │   1.  Simulate Normal Traffic                       │
  │   2.  Simulate Attack (Brute Force)                 │
  │   3.  Simulate Attack (Rapid Requests / DoS)        │
  │   4.  Simulate Attack (Directory Scan)              │
  │   5.  Simulate Mixed Attack                         │
  │   6.  View Event Logs                               │
  │   7.  Run Detection on Full Dataset                 │
  │   8.  Train / Retrain Model                         │
  │   9.  Show Anomaly Score Chart                      │
  │   10. Clear Logs                                    │
  │   11. About IntelliGuard                            │
  │   0.  Exit                                          │
  └─────────────────────────────────────────────────────┘{Colors.RESET}
"""

ABOUT = f"""
{Colors.CYAN}  ╔══════════════════════════════════════════════════════════════╗
  ║              ABOUT INTELLIGUARD IDS                          ║
  ╠══════════════════════════════════════════════════════════════╣
  ║                                                              ║
  ║  IntelliGuard uses an Isolation Forest ML model to           ║
  ║  detect anomalous network and login activity in real-time.   ║
  ║                                                              ║
  ║  HOW IT WORKS:                                               ║
  ║  ─────────────────────────────────────────────────────────   ║
  ║  1. Baseline Learning:                                       ║
  ║     The model trains on normal traffic data, learning        ║
  ║     patterns like typical request rates, login success       ║
  ║     rates, session durations, and transfer volumes.          ║
  ║                                                              ║
  ║  2. Anomaly Scoring:                                         ║
  ║     Each new event is passed through 200 isolation trees.    ║
  ║     Events that isolate quickly = anomalies (low score).     ║
  ║     Events that take many splits = normal (high score).      ║
  ║                                                              ║
  ║  3. Alert Severity:                                          ║
  ║     ● LOW     → score > -0.1                                 ║
  ║     ● MEDIUM  → score > -0.3                                 ║
  ║     ● HIGH    → score ≤ -0.5                                 ║
  ║                                                              ║
  ║  4. Explanation Engine:                                      ║
  ║     Rule-based post-processing explains WHY an event        ║
  ║     was flagged in plain English.                            ║
  ║                                                              ║
  ║  DETECTS:                                                    ║
  ║  ● Brute-force login attacks                                 ║
  ║  ● Rate-based attacks (DoS / flood)                          ║
  ║  ● Directory/port scanning                                   ║
  ║  ● Off-hours anomalous access                                ║
  ║  ● Data exfiltration patterns                                ║
  ║                                                              ║
  ║  Made By : Monish Paramasivam                                ║
  ║  Model   : Isolation Forest (scikit-learn)                   ║
  ║  Stack   : Python 3, scikit-learn, pandas, numpy             ║
  ╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""


# ── Helper ────────────────────────────────────────────────────────────────────

def pause(msg="  Press Enter to continue..."):
    input(f"\n{Colors.dim(msg)}")


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def ask_int(prompt, lo, hi):
    while True:
        try:
            v = int(input(prompt))
            if lo <= v <= hi:
                return v
            print(Colors.yellow(f"  [!] Enter a number between {lo} and {hi}."))
        except ValueError:
            print(Colors.yellow("  [!] Invalid input."))


# ── Menu Actions ──────────────────────────────────────────────────────────────

def menu_normal_traffic(pipeline: DetectionPipeline):
    clear()
    print(BANNER)
    print(Colors.bold("  ── NORMAL TRAFFIC SIMULATION ──\n"))
    n = ask_int("  How many events? (5–100): ", 5, 100)
    events = stream_normal_traffic(n_events=n)
    print(f"\n  {Colors.bold('[*] Running detection on generated events...')}")
    pipeline.process_stream(events)
    pause()


def menu_attack(pipeline: DetectionPipeline, attack_type: str):
    clear()
    print(BANNER)
    labels = {
        "brute_force":   "BRUTE FORCE ATTACK SIMULATION",
        "rapid_request": "RAPID REQUEST / DoS SIMULATION",
        "scan":          "DIRECTORY SCAN SIMULATION",
        "mixed":         "MIXED ATTACK SIMULATION",
    }
    print(Colors.red(f"  ── {labels.get(attack_type, 'ATTACK SIMULATION')} ──\n"))
    n = ask_int("  How many attack events? (5–50): ", 5, 50)
    events = stream_attack_traffic(attack_type=attack_type, n_events=n)
    print(f"\n  {Colors.bold('[*] Running detection on attack events...')}")
    pipeline.process_stream(events)
    pause()


def menu_view_logs(logger: EventLogger):
    clear()
    print(BANNER)
    print(Colors.bold("  ── EVENT LOG VIEWER ──"))
    n = ask_int("  How many recent entries to show? (10–100): ", 10, 100)
    logger.view_logs(n=n)
    pause()


def menu_run_dataset(pipeline: DetectionPipeline):
    clear()
    print(BANNER)
    print(Colors.bold("  ── FULL DATASET DETECTION ──\n"))
    print("  Running Isolation Forest on the full network event dataset...")
    print("  This will generate an anomaly score chart and model metrics.\n")
    pipeline.run_on_dataset()
    pause()


def menu_train(pipeline: DetectionPipeline):
    clear()
    print(BANNER)
    print(Colors.bold("  ── MODEL TRAINING ──\n"))
    print("  This will regenerate the dataset and retrain the Isolation Forest model.")
    confirm = input("  Proceed? (y/n): ").strip().lower()
    if confirm == "y":
        pipeline.setup(force_retrain=True)
        print(Colors.green("\n  [✓] Model retrained successfully."))
    else:
        print(Colors.yellow("  [!] Training cancelled."))
    pause()


def menu_score_chart(logger: EventLogger, pipeline: DetectionPipeline):
    """Show anomaly score visualization from recent log data."""
    clear()
    print(BANNER)
    print(Colors.bold("  ── ANOMALY SCORE CHART ──\n"))

    import csv
    import os
    log_file = logger.log_file

    if not os.path.exists(log_file):
        print(Colors.yellow("  [!] No log data found. Run a simulation first."))
        pause()
        return

    scores, labels = [], []
    with open(log_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                scores.append(float(row["raw_score"]))
                labels.append(row["label"])
            except (ValueError, KeyError):
                pass

    if not scores:
        print(Colors.yellow("  [!] No score data available yet."))
        pause()
        return

    # Show last 30 entries
    scores = scores[-30:]
    labels = labels[-30:]

    print(f"  Showing anomaly scores for last {len(scores)} events:\n")
    print(f"  {Colors.DIM}( ░ = normal   █ = suspicious ){Colors.RESET}\n")
    viz = visualize_scores(scores, labels, width=65)
    print(viz)
    pause()


def menu_clear_logs(logger: EventLogger):
    clear()
    print(BANNER)
    confirm = input("  Clear all logs? This cannot be undone. (y/n): ").strip().lower()
    if confirm == "y":
        logger.clear_logs()
    else:
        print(Colors.yellow("  [!] Clear cancelled."))
    pause()


def menu_about():
    clear()
    print(BANNER)
    print(ABOUT)
    pause()


# ── Main Loop ─────────────────────────────────────────────────────────────────

def main():
    clear()
    print(BANNER)
    print(Colors.cyan("  [*] Initializing IntelliGuard..."))

    pipeline = DetectionPipeline()
    logger   = EventLogger()

    # Bootstrap: load or train model at startup
    pipeline.setup(force_retrain=False)

    print(Colors.green("  [✓] System ready.\n"))
    time.sleep(0.8)

    while True:
        clear()
        print(BANNER)

        # Show live stats in menu header
        stats = logger.get_stats()
        if stats:
            print(
                f"  {Colors.bold('System Status:')} "
                f"Events logged: {stats.get('total', 0)} | "
                f"Suspicious: {Colors.red(str(stats.get('suspicious', 0)))} | "
                f"Normal: {Colors.green(str(stats.get('normal', 0)))}\n"
            )

        print(MENU)

        choice = input(f"  {Colors.bold('Select option [0-11]:')} ").strip()

        if choice == "1":
            menu_normal_traffic(pipeline)
        elif choice == "2":
            menu_attack(pipeline, "brute_force")
        elif choice == "3":
            menu_attack(pipeline, "rapid_request")
        elif choice == "4":
            menu_attack(pipeline, "scan")
        elif choice == "5":
            menu_attack(pipeline, "mixed")
        elif choice == "6":
            menu_view_logs(logger)
        elif choice == "7":
            menu_run_dataset(pipeline)
        elif choice == "8":
            menu_train(pipeline)
        elif choice == "9":
            menu_score_chart(logger, pipeline)
        elif choice == "10":
            menu_clear_logs(logger)
        elif choice == "11":
            menu_about()
        elif choice == "0":
            clear()
            print(BANNER)
            print(Colors.cyan("  Shutting down IntelliGuard. Stay secure.\n"))
            print(Colors.dim("  Made By Monish Paramasivam\n"))
            break
        else:
            print(Colors.yellow("\n  [!] Invalid option. Please enter 0–11."))
            time.sleep(1)


if __name__ == "__main__":
    main()
