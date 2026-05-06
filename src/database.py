import sqlite3
from datetime import datetime\

DB_NAME = "netwatch.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Scan history
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT,
            timestamp TEXT,
            device_count INTEGER
        )
    """)

    # Device logs
    c.execute("""
        CREATE TABLE IF NOT EXISTS device_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT,
            ip TEXT,
            mac TEXT,
            risk TEXT,
            score INTEGER,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


def log_scan(network, device_count):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
        INSERT INTO scans (network, timestamp, device_count)
        VALUES (?, ?, ?)
    """, (network, datetime.now().isoformat(), device_count))

    conn.commit()
    conn.close()


def log_devices(network, devices):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    for d in devices:
        c.execute("""
            INSERT INTO device_logs (network, ip, mac, risk, score, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            network,
            d.get("ip"),
            d.get("mac"),
            d.get("level", "LOW"),
            d.get("score", 0),
            datetime.now().isoformat()
        ))

    conn.commit()
    conn.close()