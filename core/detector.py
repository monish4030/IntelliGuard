"""
=============================================================
  IntelliGuard - Detection Pipeline
  File: core/detector.py
  Description: Orchestrates the full detection workflow:
               load/train model → receive events → predict
               → log → alert. Central coordinator module.
  Made By Monish Paramasivam
=============================================================
"""

import os
import json
from core.ml_engine import AnomalyDetector, visualize_scores
from core.logger import EventLogger, Colors


def load_config(config_path="config.json"):
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.join(base, config_path)
    with open(full_path, "r") as f:
        return json.load(f)


class DetectionPipeline:
    """
    Full detection pipeline that ties together:
    - Model loading / training
    - Event intake and feature extraction
    - Anomaly scoring and classification
    - Logging and alert dispatch
    """

    def __init__(self):
        self.detector = AnomalyDetector()
        self.logger   = EventLogger()
        self.config   = load_config()
        self._model_ready = False

    def setup(self, force_retrain: bool = False) -> None:
        """
        Prepare the detection pipeline.
        Loads a saved model if available, otherwise trains a new one.

        Args:
            force_retrain: If True, always retrain even if model exists.
        """
        if not force_retrain:
            loaded = self.detector.load()
            if loaded:
                self._model_ready = True
                print(Colors.green("  [✓] Pre-trained model loaded from disk."))
                return

        # No saved model — train from scratch
        print(Colors.cyan("  [*] No saved model found. Training new model..."))
        self.detector.train(verbose=True)
        self._model_ready = True

    def _ensure_ready(self) -> None:
        """Ensure the model is ready before making predictions."""
        if not self._model_ready:
            self.setup()

    # ── Single Event Processing ───────────────────────────────────────────────

    def process_event(self, event: dict, quiet: bool = False) -> dict:
        """
        Process a single event: detect → log → alert if needed.

        Args:
            event: Raw event dictionary from simulator or real source.
            quiet: If True, suppress console output.

        Returns:
            Detection result dictionary.
        """
        self._ensure_ready()

        result = self.detector.predict(event)
        record = self.logger.log_event(event, result)

        if not quiet:
            if result["is_anomaly"]:
                self.logger.print_alert(record)
            else:
                self.logger.print_normal(record)

        return result

    # ── Batch / Stream Processing ─────────────────────────────────────────────

    def process_stream(self, events: list, show_alerts_only: bool = False) -> dict:
        """
        Process a stream of events and return summary statistics.

        Args:
            events:           List of event dicts to process.
            show_alerts_only: If True, only print suspicious events.

        Returns:
            Summary dict with counts and score list.
        """
        self._ensure_ready()

        results       = []
        scores        = []
        labels        = []
        alert_count   = 0
        normal_count  = 0

        print()
        for event in events:
            result = self.detector.predict(event)
            record = self.logger.log_event(event, result)

            scores.append(result["raw_score"])
            labels.append(result["label"])

            if result["is_anomaly"]:
                alert_count += 1
                self.logger.print_alert(record)
            else:
                normal_count += 1
                if not show_alerts_only:
                    self.logger.print_normal(record)

            results.append(result)

        # Summary
        print(f"\n  {'─' * 70}")
        print(f"  {Colors.bold('Detection Summary:')}")
        print(f"    Events Processed : {len(events)}")
        print(f"    Normal           : {Colors.green(str(normal_count))}")
        print(f"    Suspicious       : {Colors.red(str(alert_count))}")
        if alert_count > 0:
            high   = sum(1 for r in results if r["severity"] == "HIGH")
            medium = sum(1 for r in results if r["severity"] == "MEDIUM")
            low    = sum(1 for r in results if r["severity"] == "LOW")
            print(f"    → HIGH   Alerts  : {Colors.red(str(high))}")
            print(f"    → MEDIUM Alerts  : {Colors.yellow(str(medium))}")
            print(f"    → LOW    Alerts  : {Colors.cyan(str(low))}")
        print(f"  {'─' * 70}")

        return {
            "total":      len(events),
            "normal":     normal_count,
            "suspicious": alert_count,
            "scores":     scores,
            "labels":     labels,
            "results":    results,
        }

    # ── Dataset Detection (run model on CSV) ──────────────────────────────────

    def run_on_dataset(self, data_path: str = "data/network_events.csv") -> None:
        """
        Run detection on the full saved dataset and show results.

        Args:
            data_path: Relative path to the dataset CSV.
        """
        import pandas as pd

        self._ensure_ready()

        base      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        full_path = os.path.join(base, data_path)

        if not os.path.exists(full_path):
            print(Colors.yellow(f"  [!] Dataset not found at '{data_path}'."))
            print(Colors.yellow("  [!] Generating dataset..."))
            from data.dataset_generator import generate_dataset
            df = generate_dataset()
        else:
            df = pd.read_csv(full_path)

        print(f"\n  [*] Running detection on {len(df)} records from '{data_path}'...")

        result_df = self.detector.predict_batch(df)

        # Print batch anomaly score visualization
        scores = result_df["raw_score"].tolist()[:40]  # Show first 40 for readability
        labels = result_df["label"].tolist()[:40]
        viz    = visualize_scores(scores, labels)
        print(f"\n{viz}\n")

        # Accuracy if ground truth available
        if "is_attack" in df.columns:
            from sklearn.metrics import classification_report, confusion_matrix
            y_true = df["is_attack"].astype(int)
            y_pred = result_df["is_anomaly"].astype(int)

            print(f"  {Colors.bold('Model Performance (vs. labeled data):')}")
            print("  " + "─" * 50)

            # Confusion matrix
            cm = confusion_matrix(y_true, y_pred)
            tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
            print(f"  True Negatives  (correct normal)    : {tn}")
            print(f"  True Positives  (correct attack)    : {tp}")
            print(f"  False Positives (false alarm)       : {fp}")
            print(f"  False Negatives (missed attack)     : {fn}")
            print()

            # Report
            report = classification_report(
                y_true, y_pred,
                target_names=["Normal", "Attack"],
                zero_division=0
            )
            for line in report.splitlines():
                print(f"  {line}")
