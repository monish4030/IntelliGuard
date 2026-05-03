"""
=============================================================
  IntelliGuard - Dataset Generator
  File: data/dataset_generator.py
  Description: Generates synthetic network/login event data
               representing both normal and attack patterns.
  Made By Monish Paramasivam
=============================================================
"""

import numpy as np
import pandas as pd
import random
import json
import os
from datetime import datetime, timedelta


def load_config(config_path="config.json"):
    """Load configuration from JSON file."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.join(base, config_path)
    with open(full_path, "r") as f:
        return json.load(f)


def generate_ip():
    """Generate a random IPv4 address."""
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_normal_event(base_time, config):
    """
    Generate a single normal network/login event.
    Normal behavior = low request rate, low failure rate, varied IPs.
    """
    sim = config["simulation"]
    return {
        "timestamp": base_time + timedelta(seconds=random.randint(0, 3600)),
        "ip_address": generate_ip(),
        "request_rate": random.uniform(1, sim["normal_request_rate_max"]),      # Requests per minute
        "failed_logins": random.randint(0, 1),                                   # Very few failures
        "session_duration": random.uniform(30, 600),                             # 30s - 10min
        "unique_endpoints": random.randint(1, 8),                                # Normal browsing
        "bytes_transferred": random.uniform(500, 50000),                         # Reasonable payload
        "login_attempts": random.randint(1, 2),                                  # 1-2 attempts
        "hour_of_day": random.randint(8, 20),                                    # Business hours
        "is_attack": 0
    }


def generate_attack_event(base_time, config, attack_type="brute_force"):
    """
    Generate a single attack event.
    Attack behavior = high request rate, high failure rate, single IP hammering.

    Attack Types:
    - brute_force: Many failed logins from same IP rapidly
    - rapid_request: Massive request volume (DoS-style)
    - anomalous: Unusual combination of features
    """
    sim = config["simulation"]

    if attack_type == "brute_force":
        # Brute force: same IP, many failed attempts, quick succession
        attacker_ip = generate_ip()
        return {
            "timestamp": base_time + timedelta(seconds=random.randint(0, 300)),
            "ip_address": attacker_ip,
            "request_rate": random.uniform(15, 40),
            "failed_logins": random.randint(8, 30),                              # Many failures
            "session_duration": random.uniform(1, 30),                           # Short sessions
            "unique_endpoints": random.randint(1, 2),                            # Targeting login
            "bytes_transferred": random.uniform(200, 2000),                      # Low payload
            "login_attempts": random.randint(10, 50),                            # Repeated attempts
            "hour_of_day": random.randint(0, 23),                                # Any hour
            "is_attack": 1
        }

    elif attack_type == "rapid_request":
        # Rate-based attack: very high request frequency
        return {
            "timestamp": base_time + timedelta(seconds=random.randint(0, 60)),
            "ip_address": generate_ip(),
            "request_rate": random.uniform(sim["attack_request_rate_min"], 200), # Extreme rate
            "failed_logins": random.randint(0, 3),
            "session_duration": random.uniform(5, 60),
            "unique_endpoints": random.randint(1, 3),
            "bytes_transferred": random.uniform(100, 500),                       # Small packets, high volume
            "login_attempts": random.randint(1, 5),
            "hour_of_day": random.randint(0, 23),
            "is_attack": 1
        }

    else:  # anomalous
        # Unusual pattern that deviates from normal baselines
        return {
            "timestamp": base_time + timedelta(seconds=random.randint(0, 1800)),
            "ip_address": generate_ip(),
            "request_rate": random.uniform(25, 60),
            "failed_logins": random.randint(5, 15),
            "session_duration": random.uniform(1, 10),
            "unique_endpoints": random.randint(10, 20),                          # Scanning many endpoints
            "bytes_transferred": random.uniform(100000, 500000),                 # Exfiltration attempt
            "login_attempts": random.randint(5, 20),
            "hour_of_day": random.randint(1, 4),                                 # Night-time activity
            "is_attack": 1
        }


def generate_dataset(n_normal=500, n_attacks=50, save_path="data/network_events.csv"):
    """
    Generate a labeled dataset of normal and attack events.

    Args:
        n_normal: Number of normal events to generate
        n_attacks: Number of attack events to generate
        save_path: CSV output path

    Returns:
        pd.DataFrame: The complete dataset
    """
    config = load_config()
    events = []
    base_time = datetime(2025, 1, 1, 0, 0, 0)

    # --- Generate Normal Events ---
    print(f"  [+] Generating {n_normal} normal traffic events...")
    for _ in range(n_normal):
        events.append(generate_normal_event(base_time, config))

    # --- Generate Attack Events (mixed types) ---
    attack_types = ["brute_force", "rapid_request", "anomalous"]
    per_type = n_attacks // len(attack_types)
    remainder = n_attacks % len(attack_types)

    print(f"  [+] Generating {n_attacks} attack events (brute force / rapid requests / anomalous)...")
    for attack_type in attack_types:
        count = per_type + (1 if remainder > 0 else 0)
        remainder -= 1
        for _ in range(count):
            events.append(generate_attack_event(base_time, config, attack_type))

    # --- Shuffle and build DataFrame ---
    random.shuffle(events)
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    # --- Save to CSV ---
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.join(base, save_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    df.to_csv(full_path, index=False)
    print(f"  [+] Dataset saved to: {save_path}")
    print(f"  [+] Total records: {len(df)} | Normal: {n_normal} | Attacks: {n_attacks}")
    return df


if __name__ == "__main__":
    print("\n[IntelliGuard] Generating Sample Dataset...")
    df = generate_dataset(n_normal=500, n_attacks=80)
    print("\nDataset preview (first 5 rows):")
    print(df.head())
    print(f"\nClass distribution:\n{df['is_attack'].value_counts()}")
