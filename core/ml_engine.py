"""
=============================================================
  IntelliGuard - Machine Learning Engine
  File: core/ml_engine.py
  Description: Implements Isolation Forest anomaly detection.
               Handles model training, prediction, scoring,
               and human-readable explanation of detections.
  Made By Monish Paramasivam
=============================================================

  HOW ISOLATION FOREST WORKS:
  ─────────────────────────────────────────────────────────
  Isolation Forest is an unsupervised anomaly detection
  algorithm. It works by randomly selecting a feature,
  then randomly selecting a split value between that
  feature's min and max values.

  Key intuition:
  - Anomalies are "few and different" — they are isolated
    much faster (require fewer splits) than normal points.
  - Normal points cluster together and take more splits
    to isolate.
  - The anomaly score reflects average path length across
    all trees. Short path = anomaly. Long path = normal.

  Score interpretation:
  - Score close to  1.0  → likely normal
  - Score close to -1.0  → likely anomaly
  ─────────────────────────────────────────────────────────
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ── Feature columns used for training/inference ─────────────────────────────
FEATURE_COLUMNS = [
    "request_rate",
    "failed_logins",
    "session_duration",
    "unique_endpoints",
    "bytes_transferred",
    "login_attempts",
    "hour_of_day"
]

MODEL_PATH  = "models/isolation_forest.pkl"
SCALER_PATH = "models/scaler.pkl"


def load_config(config_path="config.json"):
    """Load configuration from JSON file."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.join(base, config_path)
    with open(full_path, "r") as f:
        return json.load(f)


def _resolve(relative_path):
    """Resolve path relative to project root."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)


class AnomalyDetector:
    """
    Isolation Forest–based anomaly detector for network/login events.

    Workflow:
      1. train()  → fit on normal-like data, save model + scaler
      2. predict() → score new events and classify them
      3. explain() → generate human-readable reason for each alert
    """

    def __init__(self):
        self.model   = None
        self.scaler  = StandardScaler()
        self.config  = load_config()
        self.trained = False

    # ── Training ─────────────────────────────────────────────────────────────

    def train(self, df: pd.DataFrame = None, verbose: bool = True) -> None:
        """
        Train the Isolation Forest on the provided dataset.
        If no dataset is provided, auto-generates one.

        Args:
            df: DataFrame with feature columns and optional 'is_attack' label.
            verbose: Whether to print progress updates.
        """
        if df is None:
            if verbose:
                print("\n  [*] No dataset provided — generating synthetic data...")
            from data.dataset_generator import generate_dataset
            df = generate_dataset(n_normal=500, n_attacks=80)

        # Use only normal events for training (unsupervised anomaly detection)
        # In production you'd train on clean/known-good traffic only.
        if "is_attack" in df.columns:
            train_df = df[df["is_attack"] == 0].copy()
        else:
            train_df = df.copy()

        if verbose:
            print(f"\n  [*] Training on {len(train_df)} normal traffic samples...")
            print(f"  [*] Features used: {FEATURE_COLUMNS}")

        X = train_df[FEATURE_COLUMNS].values

        # Scale features — Isolation Forest benefits from normalized ranges
        X_scaled = self.scaler.fit_transform(X)

        # Build Isolation Forest
        cfg = self.config["model"]
        self.model = IsolationForest(
            n_estimators=cfg["n_estimators"],       # Number of trees
            contamination=cfg["contamination"],      # Expected anomaly fraction
            max_samples=cfg["max_samples"],
            random_state=cfg["random_state"],
            n_jobs=-1                                # Use all CPU cores
        )
        self.model.fit(X_scaled)
        self.trained = True

        # Persist model + scaler
        os.makedirs(_resolve("models"), exist_ok=True)
        joblib.dump(self.model,  _resolve(MODEL_PATH))
        joblib.dump(self.scaler, _resolve(SCALER_PATH))

        if verbose:
            print(f"  [✓] Model trained and saved to '{MODEL_PATH}'")
            print(f"  [✓] Scaler saved to '{SCALER_PATH}'")
            print(f"  [*] Contamination factor: {cfg['contamination']}")
            print(f"  [*] Trees (n_estimators): {cfg['n_estimators']}")

    # ── Loading a saved model ─────────────────────────────────────────────────

    def load(self) -> bool:
        """
        Load a pre-trained model and scaler from disk.

        Returns:
            True if loaded successfully, False otherwise.
        """
        model_path  = _resolve(MODEL_PATH)
        scaler_path = _resolve(SCALER_PATH)

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model   = joblib.load(model_path)
            self.scaler  = joblib.load(scaler_path)
            self.trained = True
            return True
        return False

    # ── Prediction ───────────────────────────────────────────────────────────

    def predict(self, event: dict) -> dict:
        """
        Predict whether a single event is anomalous.

        Args:
            event: Dictionary containing feature values for one event.

        Returns:
            dict with keys:
              - 'is_anomaly'   : bool
              - 'raw_score'    : float (Isolation Forest decision function score)
              - 'severity'     : str  ("LOW" / "MEDIUM" / "HIGH" / "NORMAL")
              - 'label'        : str  ("NORMAL" / "SUSPICIOUS")
              - 'reason'       : list[str] human-readable explanations
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call train() or load() first.")

        X = np.array([[event.get(f, 0) for f in FEATURE_COLUMNS]])
        X_scaled = self.scaler.transform(X)

        # decision_function returns scores: negative → anomaly, positive → normal
        raw_score  = float(self.model.decision_function(X_scaled)[0])
        prediction = self.model.predict(X_scaled)[0]   # -1 = anomaly, 1 = normal

        is_anomaly = (prediction == -1)
        severity   = self._get_severity(raw_score, is_anomaly)
        reasons    = self._explain(event) if is_anomaly else []

        return {
            "is_anomaly": is_anomaly,
            "raw_score":  round(raw_score, 4),
            "severity":   severity,
            "label":      "SUSPICIOUS" if is_anomaly else "NORMAL",
            "reason":     reasons
        }

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Run predictions on a full DataFrame.

        Returns:
            Original DataFrame with added columns:
            'is_anomaly', 'raw_score', 'severity', 'label'
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call train() or load() first.")

        result = df.copy()
        X = result[FEATURE_COLUMNS].values
        X_scaled = self.scaler.transform(X)

        scores      = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)

        result["raw_score"]  = scores.round(4)
        result["is_anomaly"] = (predictions == -1)
        result["severity"]   = [
            self._get_severity(s, a) for s, a in zip(scores, result["is_anomaly"])
        ]
        result["label"] = result["is_anomaly"].map({True: "SUSPICIOUS", False: "NORMAL"})
        return result

    # ── Severity Classification ───────────────────────────────────────────────

    def _get_severity(self, raw_score: float, is_anomaly: bool) -> str:
        """
        Classify severity based on anomaly score thresholds.

        Score ranges (lower = more anomalous):
          NORMAL   :  score > anomaly_score_low
          LOW      : -0.3 < score <= -0.1
          MEDIUM   : -0.5 < score <= -0.3
          HIGH     :  score <= -0.5
        """
        if not is_anomaly:
            return "NORMAL"
        thr = self.config["thresholds"]
        if raw_score > thr["anomaly_score_low"]:
            return "LOW"
        elif raw_score > thr["anomaly_score_medium"]:
            return "MEDIUM"
        else:
            return "HIGH"

    # ── Human-Readable Explanation ────────────────────────────────────────────

    def _explain(self, event: dict) -> list:
        """
        Generate human-readable reasons why an event was flagged.
        Compares event features against known normal thresholds.

        Args:
            event: Raw event dictionary.

        Returns:
            List of reason strings.
        """
        reasons = []
        thr = self.config["thresholds"]

        if event.get("failed_logins", 0) >= thr["brute_force_attempts"]:
            reasons.append(
                f"High failed login count ({event['failed_logins']} failures) — possible brute-force attack"
            )

        if event.get("request_rate", 0) >= thr["rapid_request_rate"]:
            reasons.append(
                f"Abnormal request rate ({event['request_rate']:.1f} req/min) — possible DoS/rate-based attack"
            )

        if event.get("login_attempts", 0) >= 10:
            reasons.append(
                f"Excessive login attempts ({event['login_attempts']}) from single session"
            )

        if event.get("unique_endpoints", 0) >= 10:
            reasons.append(
                f"Accessing {event['unique_endpoints']} unique endpoints — possible port/directory scan"
            )

        hour = event.get("hour_of_day", 12)
        if hour < 5 or hour > 23:
            reasons.append(
                f"Activity at unusual hour ({hour:02d}:00) — off-hours access pattern"
            )

        if event.get("bytes_transferred", 0) > 100000:
            mb = event["bytes_transferred"] / 1024 / 1024
            reasons.append(
                f"Large data transfer ({mb:.2f} MB) — possible data exfiltration"
            )

        if not reasons:
            reasons.append(
                "Statistical anomaly — event deviates significantly from learned normal patterns"
            )

        return reasons


# ── Score Visualization (text-based sparkline) ───────────────────────────────

def visualize_scores(scores: list, labels: list = None, width: int = 60) -> str:
    """
    Generate a text-based bar chart of anomaly scores.

    Args:
        scores: List of raw anomaly scores.
        labels: Optional list of labels ("NORMAL" / "SUSPICIOUS").
        width:  Width of the display in characters.

    Returns:
        Multi-line string visualization.
    """
    if not scores:
        return "No scores to visualize."

    lines = []
    lines.append("  Anomaly Score Distribution")
    lines.append("  " + "─" * width)
    lines.append(f"  {'Score':<8} {'Bar':<{width - 10}} {'Status'}")
    lines.append("  " + "─" * width)

    min_s, max_s = min(scores), max(scores)
    score_range  = max_s - min_s if max_s != min_s else 1

    for i, score in enumerate(scores):
        label     = labels[i] if labels else ("SUSPICIOUS" if score < -0.1 else "NORMAL")
        bar_len   = int((score - min_s) / score_range * (width - 22))
        bar_char  = "█" if label == "SUSPICIOUS" else "░"
        bar       = bar_char * max(1, bar_len)
        flag      = " ⚠" if label == "SUSPICIOUS" else "  "
        lines.append(f"  {score:>7.3f}  {bar:<{width-22}}{flag} {label}")

    lines.append("  " + "─" * width)
    n_suspicious = sum(1 for s in scores if s < -0.1)
    lines.append(f"  Total events: {len(scores)} | Suspicious: {n_suspicious} | Normal: {len(scores) - n_suspicious}")
    return "\n".join(lines)
