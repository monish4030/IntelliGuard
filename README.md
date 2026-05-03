# 🛡️ IntelliGuard: AI Intrusion Detection System

> **Made By Monish Paramasivam**

An advanced, portfolio-grade AI-powered Intrusion Detection System (IDS) built with Python and Machine Learning. IntelliGuard uses an **Isolation Forest** algorithm to detect anomalous network and login behavior in real time, with a clean CLI dashboard, structured logging, and severity-based alerting.

---

## 📸 Example Output

```
╔══════════════════════════════════════════════════════════════════════╗
║         AI-POWERED INTRUSION DETECTION SYSTEM  v1.0.0               ║
║  Made By: Monish Paramasivam         Powered by: Isolation Forest   ║
╚══════════════════════════════════════════════════════════════════════╝

  ══════════════════════════════════════════════════════════════
  🚨  [HIGH ALERT]  2025-06-01 03:22:11
  ══════════════════════════════════════════════════════════════
  IP Address     : 45.112.88.201
  Event Type     : BRUTE_FORCE
  Request Rate   : 38.4 req/min
  Failed Logins  : 24
  Login Attempts : 47
  Anomaly Score  : -0.6214

  DETECTION REASONS:
    ► High failed login count (24 failures) — possible brute-force attack
    ► Excessive login attempts (47) from single session
    ► Activity at unusual hour (03:00) — off-hours access pattern
  ══════════════════════════════════════════════════════════════
```

---

## 🚀 Features

| Feature | Details |
|---|---|
| **ML Model** | Isolation Forest (unsupervised anomaly detection) |
| **Attack Types** | Brute Force, Rapid Requests/DoS, Directory Scan, Mixed |
| **Severity Levels** | LOW / MEDIUM / HIGH based on anomaly score |
| **Logging** | CSV-based structured event log with timestamps |
| **Explainability** | Human-readable reason for every alert |
| **Score Visualization** | Text-based sparkline chart of anomaly scores |
| **Config-Driven** | All thresholds in `config.json` — no hardcoding |
| **Modular Code** | Clean separation: ML, simulator, logger, CLI |

---

## 📁 Project Structure

```
IntelliGuard/
│
├── main.py                    ← CLI dashboard (entry point)
├── config.json                ← Thresholds, model settings, simulation params
├── requirements.txt
├── README.md
│
├── core/
│   ├── ml_engine.py           ← Isolation Forest model: train, predict, explain
│   ├── simulator.py           ← Traffic event generators (normal + attack types)
│   ├── detector.py            ← Detection pipeline: orchestrates everything
│   └── logger.py              ← Structured CSV logging + alert formatting
│
├── data/
│   ├── dataset_generator.py   ← Synthetic dataset generator
│   └── network_events.csv     ← Generated dataset (auto-created on first run)
│
├── models/
│   ├── isolation_forest.pkl   ← Trained model (auto-created)
│   └── scaler.pkl             ← Feature scaler (auto-created)
│
└── logs/
    └── intelliguard.log       ← Event log CSV (auto-created)
```

---

## ⚙️ Setup Instructions

### 1. Clone or download the project
```bash
git clone https://github.com/yourusername/IntelliGuard.git
cd IntelliGuard
```

### 2. (Optional) Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run IntelliGuard
```bash
python main.py
```

On first launch, the system will automatically:
- Generate a synthetic training dataset
- Train the Isolation Forest model
- Save the model to `models/`

---

## 🧠 How the ML Model Works

### Algorithm: Isolation Forest

Isolation Forest is an **unsupervised anomaly detection** algorithm ideal for cybersecurity because it doesn't require labeled attack data to train.

**Core Intuition:**
> Anomalies are rare and different. They are much easier to isolate than normal data points.

**How it isolates:**
1. Randomly select a feature (e.g., `request_rate`)
2. Randomly pick a split value between the feature's min and max
3. Keep splitting until the point is isolated in its own leaf
4. Repeat across 200 trees

**Anomaly Score:**
- A point that gets isolated **quickly** (few splits) = **anomaly** → score near **-1.0**
- A point requiring **many splits** = **normal** → score near **+1.0**

**Features used for training:**

| Feature | Description |
|---|---|
| `request_rate` | Requests per minute from this IP |
| `failed_logins` | Number of failed login attempts |
| `session_duration` | How long the session lasted (seconds) |
| `unique_endpoints` | Number of different pages/endpoints accessed |
| `bytes_transferred` | Total data transferred in session |
| `login_attempts` | Total login attempts (success + failure) |
| `hour_of_day` | Time of activity (0–23) |

**Severity Classification:**

| Score Range | Severity |
|---|---|
| score > -0.10 | NORMAL |
| -0.30 < score ≤ -0.10 | LOW |
| -0.50 < score ≤ -0.30 | MEDIUM |
| score ≤ -0.50 | HIGH |

---

## 🎮 Menu Options

```
1.  Simulate Normal Traffic           → Generate and detect normal events
2.  Simulate Attack (Brute Force)     → Repeated failed logins
3.  Simulate Attack (Rapid Requests)  → High-frequency request flood
4.  Simulate Attack (Directory Scan)  → Endpoint scanning behavior
5.  Simulate Mixed Attack             → Combination of all attack types
6.  View Event Logs                   → Tabular view of recent events
7.  Run Detection on Full Dataset     → Batch mode + model metrics
8.  Train / Retrain Model             → Force retrain from fresh data
9.  Show Anomaly Score Chart          → ASCII visualization of scores
10. Clear Logs                        → Reset log file
11. About IntelliGuard                → Project info and ML explanation
0.  Exit
```

---

## 🔧 Configuration (`config.json`)

All system thresholds are configurable:

```json
{
  "model": {
    "contamination": 0.05,
    "n_estimators": 200
  },
  "thresholds": {
    "brute_force_attempts": 5,
    "rapid_request_rate": 20,
    "anomaly_score_high": -0.5,
    "anomaly_score_medium": -0.3
  }
}
```

---

## 🔮 Future Upgrade Suggestions

| Upgrade | Description |
|---|---|
| **Web Dashboard** | Flask/FastAPI + React frontend for real-time visualization |
| **Live Packet Capture** | Use `scapy` or `pyshark` to analyze real network packets |
| **Database Storage** | Replace CSV logs with SQLite or PostgreSQL |
| **Email/Slack Alerts** | Push HIGH severity alerts via SMTP or webhooks |
| **LSTM / Autoencoder** | Deep learning models for temporal sequence anomalies |
| **GeoIP Lookup** | Enrich IP data with geolocation (MaxMind GeoLite2) |
| **Docker Deployment** | Containerize for easy deployment on any host |
| **SIEM Integration** | Export logs in CEF/SYSLOG format for SIEM tools |

---

## 📦 Dependencies

```
scikit-learn >= 1.3.0   # Isolation Forest
pandas       >= 2.0.0   # Data manipulation
numpy        >= 1.24.0  # Numerical operations
joblib       >= 1.3.0   # Model persistence
```

---

## 👨‍💻 Author

**Made By Monish Paramasivam**

Built as a portfolio-grade cybersecurity project demonstrating:
- Machine Learning applied to security (anomaly detection)
- Clean modular Python architecture
- Realistic threat simulation and detection
- Production-style logging and alerting
