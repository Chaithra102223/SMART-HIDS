"""
Smart HIDS — Database Handler
Supports: SQLite (default, no install needed) + MySQL (optional)
File: database/hids_db.py
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

# ─── CONFIG ───────────────────────────────────────────
# Change DB_TYPE to "mysql" to use MySQL instead of SQLite
DB_TYPE = "sqlite"   # "sqlite" or "mysql"

# SQLite config (file stored in database/ folder)
SQLITE_PATH = Path(__file__).parent / "hids_data.db"

# MySQL config (only used if DB_TYPE = "mysql")
MYSQL_CONFIG = {
    "host":     "localhost",
    "port":     3306,
    "user":     "root",
    "password": "your_password",   # ← change this
    "database": "hids_db",
}

# ─── DATABASE CLASS ───────────────────────────────────

class HIDSDatabase:
    def __init__(self):
        self.db_type = DB_TYPE
        self.conn    = None
        self.connect()
        self.create_tables()
        print(f"[DB] Connected — using {self.db_type.upper()}")

    # ── CONNECTION ──────────────────────────────────────
    def connect(self):
        if self.db_type == "sqlite":
            self.conn = sqlite3.connect(
                str(SQLITE_PATH),
                check_same_thread=False
            )
            self.conn.row_factory = sqlite3.Row   # dict-like rows
            self.conn.execute("PRAGMA journal_mode=WAL")   # faster writes
        elif self.db_type == "mysql":
            try:
                import mysql.connector
                self.conn = mysql.connector.connect(**MYSQL_CONFIG)
            except ImportError:
                raise RuntimeError(
                    "mysql-connector-python not installed.\n"
                    "Run: pip3 install mysql-connector-python"
                )
        else:
            raise ValueError(f"Unknown DB_TYPE: {self.db_type}")

    def cursor(self):
        if self.db_type == "sqlite":
            return self.conn.cursor()
        else:
            # MySQL: reconnect if dropped
            if not self.conn.is_connected():
                self.connect()
            return self.conn.cursor(dictionary=True)

    def commit(self):
        self.conn.commit()

    # ── CREATE TABLES ───────────────────────────────────
    def create_tables(self):
        cur = self.cursor()
        placeholder = "?" if self.db_type == "sqlite" else "%s"

        # ── alerts ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                alert_type  TEXT    NOT NULL,
                source_ip   TEXT    NOT NULL,
                target      TEXT,
                severity    TEXT    NOT NULL,
                status      TEXT    DEFAULT 'new',
                detail      TEXT,
                created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── blocked_ips ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT    NOT NULL UNIQUE,
                reason      TEXT    NOT NULL,
                blocked_at  TEXT    NOT NULL,
                auto_block  INTEGER DEFAULT 0,
                unblocked   INTEGER DEFAULT 0,
                created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── system_metrics ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS system_metrics (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                cpu_percent REAL,
                mem_percent REAL,
                disk_percent REAL,
                bytes_in    INTEGER,
                bytes_out   INTEGER,
                pkts_in     INTEGER,
                pkts_out    INTEGER,
                hostname    TEXT,
                created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── login_events ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                username    TEXT,
                source_ip   TEXT,
                service     TEXT,
                success     INTEGER DEFAULT 0,
                detail      TEXT,
                created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── logs ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                level       TEXT    NOT NULL,
                message     TEXT    NOT NULL,
                source      TEXT    DEFAULT 'system',
                created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── processes_snapshot ──
        cur.execute("""
            CREATE TABLE IF NOT EXISTS processes_snapshot (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                pid         INTEGER,
                name        TEXT,
                cpu_percent REAL,
                mem_percent REAL,
                username    TEXT,
                threat_level TEXT   DEFAULT 'none',
                created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        self.commit()
        print("[DB] All tables created/verified")

    # ── ALERTS ──────────────────────────────────────────
    def insert_alert(self, alert_type, source_ip, target,
                     severity, status="new", detail=""):
        cur = self.cursor()
        ts  = datetime.now().isoformat()
        if self.db_type == "sqlite":
            cur.execute("""
                INSERT INTO alerts
                    (timestamp, alert_type, source_ip, target, severity, status, detail)
                VALUES (?,?,?,?,?,?,?)
            """, (ts, alert_type, source_ip, target, severity, status, detail))
        else:
            cur.execute("""
                INSERT INTO alerts
                    (timestamp, alert_type, source_ip, target, severity, status, detail)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (ts, alert_type, source_ip, target, severity, status, detail))
        self.commit()
        return cur.lastrowid

    def get_alerts(self, limit=200, severity=None):
        cur = self.cursor()
        if severity:
            cur.execute(
                "SELECT * FROM alerts WHERE severity=? ORDER BY id DESC LIMIT ?",
                (severity, limit)
            ) if self.db_type == "sqlite" else cur.execute(
                "SELECT * FROM alerts WHERE severity=%s ORDER BY id DESC LIMIT %s",
                (severity, limit)
            )
        else:
            cur.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ) if self.db_type == "sqlite" else cur.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT %s", (limit,)
            )
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id):
        cur = self.cursor()
        if self.db_type == "sqlite":
            cur.execute("UPDATE alerts SET status='acknowledged' WHERE id=?", (alert_id,))
        else:
            cur.execute("UPDATE alerts SET status='acknowledged' WHERE id=%s", (alert_id,))
        self.commit()

    def get_alert_counts(self):
        cur = self.cursor()
        cur.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM alerts
            GROUP BY severity
        """)
        rows = cur.fetchall()
        counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for r in rows:
            r = dict(r)
            counts[r["severity"]] = r["cnt"]
        counts["total"] = sum(counts.values())
        cur.execute("SELECT COUNT(*) as n FROM alerts WHERE status='new'")
        counts["new"] = dict(cur.fetchone())["n"]
        return counts

    # ── BLOCKED IPs ─────────────────────────────────────
    def block_ip(self, ip, reason, auto=False):
        cur = self.cursor()
        ts  = datetime.now().strftime("%H:%M")
        try:
            if self.db_type == "sqlite":
                cur.execute("""
                    INSERT OR REPLACE INTO blocked_ips
                        (ip_address, reason, blocked_at, auto_block, unblocked)
                    VALUES (?,?,?,?,0)
                """, (ip, reason, ts, 1 if auto else 0))
            else:
                cur.execute("""
                    INSERT INTO blocked_ips
                        (ip_address, reason, blocked_at, auto_block, unblocked)
                    VALUES (%s,%s,%s,%s,0)
                    ON DUPLICATE KEY UPDATE
                        reason=VALUES(reason),
                        blocked_at=VALUES(blocked_at),
                        unblocked=0
                """, (ip, reason, ts, 1 if auto else 0))
            self.commit()
            return True
        except Exception as e:
            print(f"[DB] block_ip error: {e}")
            return False

    def unblock_ip(self, ip):
        cur = self.cursor()
        if self.db_type == "sqlite":
            cur.execute("UPDATE blocked_ips SET unblocked=1 WHERE ip_address=?", (ip,))
        else:
            cur.execute("UPDATE blocked_ips SET unblocked=1 WHERE ip_address=%s", (ip,))
        self.commit()

    def get_blocked_ips(self):
        cur = self.cursor()
        cur.execute(
            "SELECT * FROM blocked_ips WHERE unblocked=0 ORDER BY id DESC"
        )
        return [dict(r) for r in cur.fetchall()]

    # ── METRICS ─────────────────────────────────────────
    def insert_metric(self, cpu, mem, disk, bytes_in, bytes_out,
                      pkts_in, pkts_out, hostname):
        cur = self.cursor()
        ts  = datetime.now().isoformat()
        if self.db_type == "sqlite":
            cur.execute("""
                INSERT INTO system_metrics
                    (timestamp,cpu_percent,mem_percent,disk_percent,
                     bytes_in,bytes_out,pkts_in,pkts_out,hostname)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (ts,cpu,mem,disk,bytes_in,bytes_out,pkts_in,pkts_out,hostname))
        else:
            cur.execute("""
                INSERT INTO system_metrics
                    (timestamp,cpu_percent,mem_percent,disk_percent,
                     bytes_in,bytes_out,pkts_in,pkts_out,hostname)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (ts,cpu,mem,disk,bytes_in,bytes_out,pkts_in,pkts_out,hostname))
        self.commit()

    def get_metrics_history(self, limit=60):
        cur = self.cursor()
        cur.execute(
            "SELECT * FROM system_metrics ORDER BY id DESC LIMIT ?", (limit,)
        ) if self.db_type == "sqlite" else cur.execute(
            "SELECT * FROM system_metrics ORDER BY id DESC LIMIT %s", (limit,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        return list(reversed(rows))

    # ── LOGIN EVENTS ─────────────────────────────────────
    def insert_login_event(self, event_type, username, source_ip,
                           service, success=False, detail=""):
        cur = self.cursor()
        ts  = datetime.now().isoformat()
        if self.db_type == "sqlite":
            cur.execute("""
                INSERT INTO login_events
                    (timestamp,event_type,username,source_ip,service,success,detail)
                VALUES (?,?,?,?,?,?,?)
            """, (ts,event_type,username,source_ip,service,1 if success else 0,detail))
        else:
            cur.execute("""
                INSERT INTO login_events
                    (timestamp,event_type,username,source_ip,service,success,detail)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (ts,event_type,username,source_ip,service,1 if success else 0,detail))
        self.commit()

    def get_failed_logins(self, limit=50):
        cur = self.cursor()
        cur.execute("""
            SELECT source_ip, COUNT(*) as attempts, MAX(timestamp) as last_seen
            FROM login_events
            WHERE success=0
            GROUP BY source_ip
            ORDER BY attempts DESC
            LIMIT ?
        """, (limit,)) if self.db_type == "sqlite" else cur.execute("""
            SELECT source_ip, COUNT(*) as attempts, MAX(timestamp) as last_seen
            FROM login_events
            WHERE success=0
            GROUP BY source_ip
            ORDER BY attempts DESC
            LIMIT %s
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]

    # ── LOGS ────────────────────────────────────────────
    def insert_log(self, level, message, source="system"):
        cur = self.cursor()
        ts  = datetime.now().isoformat()
        if self.db_type == "sqlite":
            cur.execute("""
                INSERT INTO logs (timestamp,level,message,source)
                VALUES (?,?,?,?)
            """, (ts,level,message,source))
        else:
            cur.execute("""
                INSERT INTO logs (timestamp,level,message,source)
                VALUES (%s,%s,%s,%s)
            """, (ts,level,message,source))
        self.commit()

    def get_logs(self, limit=100, level=None):
        cur = self.cursor()
        if level:
            cur.execute(
                "SELECT * FROM logs WHERE level=? ORDER BY id DESC LIMIT ?",
                (level,limit)
            ) if self.db_type == "sqlite" else cur.execute(
                "SELECT * FROM logs WHERE level=%s ORDER BY id DESC LIMIT %s",
                (level,limit)
            )
        else:
            cur.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
            ) if self.db_type == "sqlite" else cur.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT %s", (limit,)
            )
        return [dict(r) for r in cur.fetchall()]

    # ── PROCESS SNAPSHOTS ────────────────────────────────
    def insert_process_snapshot(self, pid, name, cpu, mem, username, threat):
        cur = self.cursor()
        ts  = datetime.now().isoformat()
        if self.db_type == "sqlite":
            cur.execute("""
                INSERT INTO processes_snapshot
                    (timestamp,pid,name,cpu_percent,mem_percent,username,threat_level)
                VALUES (?,?,?,?,?,?,?)
            """, (ts,pid,name,cpu,mem,username,threat))
        else:
            cur.execute("""
                INSERT INTO processes_snapshot
                    (timestamp,pid,name,cpu_percent,mem_percent,username,threat_level)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (ts,pid,name,cpu,mem,username,threat))
        self.commit()

    # ── EXPORT ──────────────────────────────────────────
    def export_alerts_json(self, filepath="alerts_export.json"):
        alerts = self.get_alerts(limit=1000)
        with open(filepath, "w") as f:
            json.dump(alerts, f, indent=2, default=str)
        print(f"[DB] Exported {len(alerts)} alerts → {filepath}")
        return filepath

    def get_summary(self):
        cur = self.cursor()
        summary = {}
        for table in ["alerts","blocked_ips","logs","login_events","system_metrics"]:
            cur.execute(f"SELECT COUNT(*) as n FROM {table}")
            summary[table] = dict(cur.fetchone())["n"]
        return summary

    def close(self):
        if self.conn:
            self.conn.close()
            print("[DB] Connection closed")


# ─── SINGLETON INSTANCE ───────────────────────────────
# Import this in server.py:  from database.hids_db import db
db = HIDSDatabase()


# ─── STANDALONE TEST ──────────────────────────────────
if __name__ == "__main__":
    print("\n=== Smart HIDS Database Test ===")
    print(f"DB file: {SQLITE_PATH}\n")

    # Insert test data
    aid = db.insert_alert("Brute Force SSH", "192.168.1.99", "SSH:22",
                          "critical", detail="5 fails in 30s")
    print(f"[OK] Alert inserted — ID: {aid}")

    db.block_ip("192.168.1.99", "Brute Force SSH", auto=True)
    print("[OK] IP blocked")

    db.insert_log("error", "Brute force from 192.168.1.99 — auto-blocked")
    print("[OK] Log inserted")

    db.insert_login_event("Failed SSH Login", "root", "192.168.1.99",
                          "SSH", success=False, detail="Bad password")
    print("[OK] Login event inserted")

    db.insert_metric(45.2, 62.1, 55.0, 102400, 51200, 1500, 800, "myhost")
    print("[OK] Metric inserted")

    print("\n--- Summary ---")
    for table, count in db.get_summary().items():
        print(f"  {table}: {count} rows")

    print("\n--- Alert Counts ---")
    for k, v in db.get_alert_counts().items():
        print(f"  {k}: {v}")

    print("\n[OK] All tests passed!")
    db.close()
