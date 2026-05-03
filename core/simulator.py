"""
=============================================================
  IntelliGuard - Traffic Simulator
  File: core/simulator.py
  Description: Simulates realistic network/login events for
               both normal traffic and attack scenarios.
               Feeds events into the detection pipeline.
  Made By Monish Paramasivam
=============================================================
"""

import random
import time
import json
import os
from datetime import datetime


def load_config(config_path="config.json"):
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.join(base, config_path)
    with open(full_path, "r") as f:
        return json.load(f)


# ── Known IP pools for realism ────────────────────────────────────────────────
NORMAL_IP_POOL = [
    f"192.168.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(20)
]
ATTACK_IP_POOL = [
    f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    for _ in range(5)
]

# ── Common endpoints for realism ──────────────────────────────────────────────
NORMAL_ENDPOINTS  = ["/home", "/dashboard", "/profile", "/api/data", "/logout"]
ATTACK_ENDPOINTS  = ["/login", "/admin", "/wp-admin", "/api/auth", "/root"]
SCAN_ENDPOINTS    = [
    "/admin", "/login", "/register", "/api/v1", "/config",
    "/backup", "/db", "/shell", "/env", "/.git", "/phpmyadmin"
]


def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Normal Traffic Event ──────────────────────────────────────────────────────

def simulate_normal_event() -> dict:
    """
    Simulate a single normal user interaction.
    Characterized by:
    - Low, steady request rate
    - Rare failed logins (typos happen)
    - Regular business hours activity
    - Modest data transfer
    """
    config = load_config()
    sim    = config["simulation"]

    return {
        "timestamp":        _now_str(),
        "ip_address":       random.choice(NORMAL_IP_POOL),
        "request_rate":     round(random.uniform(1.0, sim["normal_request_rate_max"]), 2),
        "failed_logins":    random.choices([0, 1], weights=[95, 5])[0],
        "session_duration": round(random.uniform(30, 600), 1),
        "unique_endpoints": random.randint(1, 5),
        "bytes_transferred":round(random.uniform(1000, 40000), 2),
        "login_attempts":   random.randint(1, 2),
        "hour_of_day":      random.randint(8, 19),
        "event_type":       "NORMAL_ACCESS",
        "endpoint":         random.choice(NORMAL_ENDPOINTS),
    }


# ── Attack Simulation Events ──────────────────────────────────────────────────

def simulate_brute_force_event() -> dict:
    """
    Simulate a brute-force login attack.
    Characterized by:
    - Single IP hammering login endpoint
    - Many rapid login attempts
    - Very high failure rate
    - Short sessions (each attempt = new session)
    """
    attacker_ip = random.choice(ATTACK_IP_POOL)
    return {
        "timestamp":        _now_str(),
        "ip_address":       attacker_ip,
        "request_rate":     round(random.uniform(20, 60), 2),
        "failed_logins":    random.randint(8, 35),
        "session_duration": round(random.uniform(0.5, 15), 1),
        "unique_endpoints": random.randint(1, 2),
        "bytes_transferred":round(random.uniform(100, 1500), 2),
        "login_attempts":   random.randint(15, 60),
        "hour_of_day":      random.randint(0, 23),
        "event_type":       "BRUTE_FORCE",
        "endpoint":         "/login",
    }


def simulate_rapid_request_event() -> dict:
    """
    Simulate a rate-based attack (DoS / DDoS-lite).
    Characterized by:
    - Extremely high request rate
    - Many unique endpoints (scanning)
    - Minimal payload per request (probing)
    """
    return {
        "timestamp":        _now_str(),
        "ip_address":       random.choice(ATTACK_IP_POOL),
        "request_rate":     round(random.uniform(50, 250), 2),
        "failed_logins":    random.randint(0, 2),
        "session_duration": round(random.uniform(1, 30), 1),
        "unique_endpoints": random.randint(3, 8),
        "bytes_transferred":round(random.uniform(50, 800), 2),
        "login_attempts":   random.randint(1, 3),
        "hour_of_day":      random.randint(0, 23),
        "event_type":       "RAPID_REQUEST",
        "endpoint":         random.choice(ATTACK_ENDPOINTS),
    }


def simulate_scan_event() -> dict:
    """
    Simulate a port/directory scan.
    Characterized by:
    - Probing many endpoints
    - Off-hours activity
    - Large bytes (pulling index pages)
    - Late-night timestamp
    """
    return {
        "timestamp":        _now_str(),
        "ip_address":       random.choice(ATTACK_IP_POOL),
        "request_rate":     round(random.uniform(15, 45), 2),
        "failed_logins":    random.randint(2, 8),
        "session_duration": round(random.uniform(5, 120), 1),
        "unique_endpoints": random.randint(10, 20),
        "bytes_transferred":round(random.uniform(80000, 450000), 2),
        "login_attempts":   random.randint(3, 12),
        "hour_of_day":      random.randint(1, 4),
        "event_type":       "DIRECTORY_SCAN",
        "endpoint":         random.choice(SCAN_ENDPOINTS),
    }


# ── Stream Simulation ─────────────────────────────────────────────────────────

def stream_normal_traffic(n_events: int = 20, delay: float = 0.05) -> list:
    """
    Simulate a stream of normal traffic events.

    Args:
        n_events: Number of events to generate.
        delay: Pause between events (seconds) for realistic feel.

    Returns:
        List of event dictionaries.
    """
    events = []
    print(f"\n  [~] Simulating {n_events} normal traffic events...\n")
    for i in range(n_events):
        event = simulate_normal_event()
        events.append(event)
        print(
            f"  [{i+1:03d}] {event['timestamp']} | IP: {event['ip_address']:<18}"
            f"| Rate: {event['request_rate']:>6.1f} req/min | Fails: {event['failed_logins']}"
            f" | Type: {event['event_type']}"
        )
        time.sleep(delay)
    print(f"\n  [✓] Stream complete — {n_events} normal events generated.")
    return events


def stream_attack_traffic(attack_type: str = "brute_force", n_events: int = 15, delay: float = 0.05) -> list:
    """
    Simulate a stream of attack traffic events.

    Args:
        attack_type: "brute_force", "rapid_request", "scan", or "mixed"
        n_events: Number of events to generate.
        delay: Pause between events.

    Returns:
        List of event dictionaries.
    """
    events      = []
    type_labels = {
        "brute_force":   "🔓 BRUTE FORCE ATTACK",
        "rapid_request": "⚡ RAPID REQUEST FLOOD",
        "scan":          "🔍 DIRECTORY SCAN",
        "mixed":         "💀 MIXED ATTACK SIMULATION"
    }
    label = type_labels.get(attack_type, "ATTACK")
    print(f"\n  [!] Initiating {label} simulation — {n_events} events...\n")

    simulators = {
        "brute_force":   simulate_brute_force_event,
        "rapid_request": simulate_rapid_request_event,
        "scan":          simulate_scan_event,
    }

    for i in range(n_events):
        if attack_type == "mixed":
            fn = random.choice(list(simulators.values()))
        else:
            fn = simulators.get(attack_type, simulate_brute_force_event)

        event = fn()
        events.append(event)
        print(
            f"  [{i+1:03d}] {event['timestamp']} | IP: {event['ip_address']:<18}"
            f"| Rate: {event['request_rate']:>7.1f} req/min | Fails: {event['failed_logins']:>3}"
            f" | Type: {event['event_type']}"
        )
        time.sleep(delay)

    print(f"\n  [!] Attack simulation complete — {n_events} events generated.")
    return events
