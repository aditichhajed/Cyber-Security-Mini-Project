#!/usr/bin/env python3
"""
intrusion_monitor.py
Watches the intrusion.log file and detects potential security incidents such as:
- repeated decryption/key unwrap failures
- tampering detection alerts

Usage:
    python intrusion_monitor.py
"""

import os
import time
from datetime import datetime

LOG_FILE = "intrusion.log"
ALERT_LOG = "alerts.log"
THRESHOLD = 3       # number of failed attempts before raising an alert
CHECK_INTERVAL = 5  # seconds

def read_log():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()

def write_alert(message):
    ts = datetime.utcnow().isoformat() + "Z"
    with open(ALERT_LOG, "a") as f:
        f.write(f"[{ts}] ALERT: {message}\n")

def monitor():
    print("[*] Intrusion Monitor active. Watching for suspicious activity...")
    seen = 0
    while True:
        time.sleep(CHECK_INTERVAL)
        logs = read_log()
        count = len(logs)
        if count > seen:
            new_entries = logs[seen:]
            seen = count
            suspicious = [l for l in new_entries if "Failed" in l or "tampering" in l.lower()]
            if suspicious:
                print(f"[!] {len(suspicious)} suspicious activities detected.")
                if len(suspicious) >= THRESHOLD:
                    msg = f"{len(suspicious)} suspicious access attempts detected! Potential intrusion."
                    print("[⚠️] ALERT:", msg)
                    write_alert(msg)
                    # optional defensive action
                    print("[!] SecureBox temporarily locked for safety.")
                    # could rename vault or revoke keys here (simulation)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring... no new incidents.")

if __name__ == "__main__":
    monitor()
