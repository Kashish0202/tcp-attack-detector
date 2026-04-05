import csv, os, time
from datetime import datetime

LOG_FILE = "logs/alerts.csv"

def log_alert(alert):
    """Print to console and save to CSV log."""
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(
        f"[{ts}] ALERT | {alert['severity']:6} | {alert['attack_type']:15} | "
        f"{alert['src_ip']:15} -> {alert['dst_ip']}:{alert['port']} | {alert['detail']}"
    )
    _write_csv(ts, alert)

def _write_csv(ts, alert):
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=
            ['timestamp','attack_type','severity','src_ip','dst_ip','port','detail'])
        if not file_exists:
            writer.writeheader()
        writer.writerow({'timestamp': ts, **alert})
