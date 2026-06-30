import asyncio
import websockets
import json
import psutil
import os
import re
import time
import threading
import platform
import signal
import sqlite3
from datetime import datetime
from collections import deque, defaultdict
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

# ══════════════════════════════════════════════════════
#  CONFIGURATION  — change ports here if needed
# ══════════════════════════════════════════════════════
WS_PORT   = 8765    # WebSocket port
HTTP_PORT = 8080    # Dashboard port

BRUTE_THRESHOLD = 5    # failed logins before auto-block
BRUTE_WINDOW    = 60   # seconds window for brute force

# ══════════════════════════════════════════════════════
#  DATABASE SETUP  (SQLite — no install needed)
# ══════════════════════════════════════════════════════
# Database file saved next to this script
DB_PATH = Path(__file__).parent.parent / "database" / "hids_data.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def db_connect():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def db_init():
    conn = db_connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            alert_type  TEXT,
            source_ip   TEXT,
            target      TEXT,
            severity    TEXT,
            status      TEXT DEFAULT 'new',
            detail      TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT UNIQUE,
            reason      TEXT,
            blocked_at  TEXT,
            auto_block  INTEGER DEFAULT 0,
            unblocked   INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS login_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            event_type  TEXT,
            username    TEXT,
            source_ip   TEXT,
            service     TEXT,
            success     INTEGER DEFAULT 0,
            detail      TEXT
        );
        CREATE TABLE IF NOT EXISTS system_metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            cpu_percent REAL,
            mem_percent REAL,
            disk_percent REAL,
            bytes_in    INTEGER,
            bytes_out   INTEGER,
            pkts_in     INTEGER,
            pkts_out    INTEGER,
            hostname    TEXT
        );
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            level     TEXT,
            message   TEXT
        );
    """)
    conn.commit()
    conn.close()
    print(f"[DB] SQLite ready → {DB_PATH}")

# Thread-safe DB write
_db_lock = threading.Lock()

def db_write(sql, params=()):
    with _db_lock:
        try:
            conn = db_connect()
            conn.execute(sql, params)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] Write error: {e}")

def db_read(sql, params=()):
    try:
        conn = db_connect()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] Read error: {e}")
        return []

# ══════════════════════════════════════════════════════
#  IN-MEMORY STATE
# ══════════════════════════════════════════════════════
alerts        = deque(maxlen=300)
logs_mem      = deque(maxlen=600)
blocked_ips   = {}        # ip → {reason, time, auto}
failed_logins = defaultdict(list)   # ip → [timestamps]
net_history   = deque(maxlen=60)
clients       = set()
alert_id      = 0
lock          = threading.Lock()
running       = True
_prev_net     = None
_alerted_pids = set()

# System log files to watch (Linux/Mac)
LOG_FILES = [
    "/var/log/auth.log",     # Ubuntu/Debian SSH logs
    "/var/log/secure",       # RHEL/CentOS SSH logs
    "/var/log/syslog",       # General system log
    "/var/log/messages",     # RHEL general log
]

# Suspicious process names
SUSP_PROCS = {
    "nc", "ncat", "netcat", "nmap", "masscan", "hydra", "medusa",
    "john", "hashcat", "mimikatz", "meterpreter", "sqlmap",
    "dirbuster", "gobuster", "nikto", "aircrack", "tcpdump",
    "ettercap", "arpspoof", "hping3", "reverse_shell", "backdoor",
    "payload", "exploit", "keylogger", "xmrig", "minerd", "cpuminer",
}

# Ports that are suspicious (common attack tools)
SUSP_PORTS = {
    4444, 5555, 1337, 31337, 6666, 6667, 9999,
    8888, 2222, 12345, 54321, 4242, 1080, 9050,
}

# ══════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════════════════
def now():      return datetime.now().strftime("%H:%M:%S")
def now_iso():  return datetime.now().isoformat()

def add_alert(type_, ip, target, sev, status="new", detail=""):
    global alert_id
    with lock:
        alert_id += 1
        a = {
            "id":     alert_id,
            "time":   now(),
            "type":   type_,
            "ip":     ip,
            "target": target,
            "sev":    sev,
            "status": status,
            "detail": detail,
        }
        alerts.appendleft(a)

    # Save to SQLite
    db_write(
        "INSERT INTO alerts (timestamp,alert_type,source_ip,target,severity,status,detail) "
        "VALUES (?,?,?,?,?,?,?)",
        (now_iso(), type_, ip, target, sev, status, detail)
    )
    add_log(f"ALERT: {type_} from {ip} → {target}",
            "error" if sev in ("critical", "high") else "warn")
    return a

def add_log(msg, level="info"):
    with lock:
        logs_mem.appendleft({"time": now(), "level": level, "msg": str(msg)})
    # Save errors/warnings to DB
    if level in ("error", "warn", "crit"):
        db_write(
            "INSERT INTO logs (timestamp,level,message) VALUES (?,?,?)",
            (now_iso(), level, str(msg)[:500])
        )

# ══════════════════════════════════════════════════════
#  REAL SYSTEM METRICS  (actual data from your PC)
# ══════════════════════════════════════════════════════
def get_metrics():
    cpu   = psutil.cpu_percent(interval=None)
    cpc   = psutil.cpu_percent(percpu=True, interval=None)
    mem   = psutil.virtual_memory()
    disk  = psutil.disk_usage('/')
    freq  = psutil.cpu_freq()
    net   = psutil.net_io_counters()

    # Get network interface statuses
    ifaces = {}
    for name, st in psutil.net_if_stats().items():
        ifaces[name] = {"up": st.isup, "speed": st.speed}

    return {
        "cpu": {
            "percent":   round(cpu, 1),
            "per_core":  [round(x, 1) for x in cpc],
            "count":     psutil.cpu_count(logical=True),
            "physical":  psutil.cpu_count(logical=False),
            "freq_mhz":  round(freq.current, 0) if freq else 0,
        },
        "memory": {
            "percent":      round(mem.percent, 1),
            "used_gb":      round(mem.used / 1e9, 2),
            "total_gb":     round(mem.total / 1e9, 2),
            "available_gb": round(mem.available / 1e9, 2),
        },
        "disk": {
            "percent":  round(disk.percent, 1),
            "used_gb":  round(disk.used / 1e9, 1),
            "total_gb": round(disk.total / 1e9, 1),
            "free_gb":  round(disk.free / 1e9, 1),
        },
        "network": {
            "bytes_sent":    net.bytes_sent,
            "bytes_recv":    net.bytes_recv,
            "packets_sent":  net.packets_sent,
            "packets_recv":  net.packets_recv,
            "errin":         net.errin,
            "errout":        net.errout,
            "dropin":        net.dropin,
            "dropout":       net.dropout,
            "interfaces":    ifaces,
        },
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "hostname":  platform.node(),
        "platform":  platform.system(),
        "arch":      platform.machine(),
        "timestamp": now_iso(),
    }

# Network delta (traffic since last call)
_prev_net_snap = None

def get_net_delta():
    global _prev_net_snap
    curr = psutil.net_io_counters()
    if _prev_net_snap is None:
        _prev_net_snap = curr
        return {"bytes_in": 0, "bytes_out": 0, "pkts_in": 0, "pkts_out": 0}

    d = {
        "bytes_in":  max(curr.bytes_recv  - _prev_net_snap.bytes_recv,  0),
        "bytes_out": max(curr.bytes_sent  - _prev_net_snap.bytes_sent,  0),
        "pkts_in":   max(curr.packets_recv - _prev_net_snap.packets_recv, 0),
        "pkts_out":  max(curr.packets_sent - _prev_net_snap.packets_sent, 0),
    }
    _prev_net_snap = curr

    # Auto-alert on traffic spikes
    if d["bytes_in"] > 15_000_000:   # > 15 MB/s incoming
        add_alert("High Inbound Traffic Spike", "network", "interface", "medium",
                  detail=f"{d['bytes_in']//1024} KB/s inbound burst detected")
    if d["pkts_in"] > 80_000:        # > 80k packets/sec
        add_alert("Possible DDoS — Packet Flood", "network", "interface", "critical",
                  detail=f"{d['pkts_in']:,} packets/sec — possible flood attack")
    return d

# ══════════════════════════════════════════════════════
#  REAL PROCESSES  (your actual running processes)
# ══════════════════════════════════════════════════════
def get_processes():
    procs = []
    try:
        for p in psutil.process_iter(
            ['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']
        ):
            try:
                info   = p.info
                name_l = (info.get('name') or '').lower()
                threat = 'none'

                # Check if process name matches suspicious list
                for s in SUSP_PROCS:
                    if s in name_l:
                        threat = 'critical'
                        break

                # High CPU = suspicious if unknown
                if threat == 'none' and (info.get('cpu_percent') or 0) > 85:
                    threat = 'high'

                procs.append({
                    "pid":    info['pid'],
                    "name":   info['name'] or '?',
                    "cpu":    round(info.get('cpu_percent') or 0, 1),
                    "mem":    round(info.get('memory_percent') or 0, 2),
                    "status": info.get('status', '?'),
                    "user":   info.get('username') or 'system',
                    "threat": threat,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        add_log(f"Process read error: {e}", "warn")

    # Alert on new suspicious processes
    for p in procs:
        if p["threat"] == "critical" and p["pid"] not in _alerted_pids:
            _alerted_pids.add(p["pid"])
            add_alert(
                f"Suspicious Process: {p['name']}",
                "localhost", f"PID:{p['pid']}", "critical",
                detail=f"CPU:{p['cpu']}% MEM:{p['mem']}%"
            )

    procs.sort(key=lambda x: x['cpu'], reverse=True)
    return procs[:25]

# ══════════════════════════════════════════════════════
#  REAL NETWORK CONNECTIONS  (actual open connections)
# ══════════════════════════════════════════════════════
def get_connections():
    conns = []
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status in ('ESTABLISHED', 'LISTEN') and c.laddr:
                rip   = c.raddr.ip   if c.raddr else ''
                rport = c.raddr.port if c.raddr else 0
                lport = c.laddr.port

                threat = 'none'
                if rport in SUSP_PORTS or lport in SUSP_PORTS:
                    threat = 'high'
                if rip and rip in blocked_ips:
                    threat = 'critical'

                conns.append({
                    "laddr":       f"{c.laddr.ip}:{lport}",
                    "raddr":       f"{rip}:{rport}" if rip else "—",
                    "status":      c.status,
                    "pid":         c.pid or 0,
                    "threat":      threat,
                    "remote_ip":   rip,
                    "remote_port": rport,
                })
    except Exception as e:
        add_log(f"Connection read error: {e}", "warn")
    return conns[:40]

# ══════════════════════════════════════════════════════
#  BRUTE FORCE DETECTOR
# ══════════════════════════════════════════════════════
def check_brute_force(ip, service):
    """Called when a failed login is detected — auto-blocks after threshold"""
    now_ts = time.time()
    with lock:
        failed_logins[ip].append(now_ts)
        # Remove old entries outside window
        failed_logins[ip] = [
            t for t in failed_logins[ip]
            if now_ts - t < BRUTE_WINDOW
        ]
        count = len(failed_logins[ip])

    if count >= BRUTE_THRESHOLD and ip not in blocked_ips:
        # Auto-block this IP
        with lock:
            blocked_ips[ip] = {
                "reason": f"Auto: Brute Force {service}",
                "time":   datetime.now().strftime("%H:%M"),
                "count":  count,
                "auto":   True,
            }
        db_write(
            "INSERT OR REPLACE INTO blocked_ips "
            "(ip_address,reason,blocked_at,auto_block,unblocked) VALUES (?,?,?,1,0)",
            (ip, f"Auto: Brute Force {service}", datetime.now().strftime("%H:%M"))
        )
        add_alert(
            f"BRUTE FORCE AUTO-BLOCKED — {service}", ip,
            f"{service} login", "critical",
            detail=f"{count} failed attempts in {BRUTE_WINDOW}s — IP auto-blocked"
        )
        print(f"[HIDS] AUTO-BLOCKED: {ip} — {count} {service} failures")

# ══════════════════════════════════════════════════════
#  REAL LOG FILE WATCHER  (reads your actual auth.log)
# ══════════════════════════════════════════════════════
def parse_log_line(line):
    """Parse one line from auth.log / secure / syslog"""

    # ── SSH Failed Password ──────────────────────────
    m = re.search(
        r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)', line
    )
    if m:
        user, ip = m.group(1), m.group(2)
        check_brute_force(ip, "SSH")
        add_alert("Failed SSH Login", ip, "SSH:22", "high",
                  detail=f"Username: {user}")
        db_write(
            "INSERT INTO login_events "
            "(timestamp,event_type,username,source_ip,service,success,detail) "
            "VALUES (?,?,?,?,?,0,?)",
            (now_iso(), "Failed SSH Login", user, ip, "SSH", f"Bad password")
        )
        return

    # ── SSH Successful Login ─────────────────────────
    m = re.search(
        r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)', line
    )
    if m:
        user, ip = m.group(1), m.group(2)
        add_log(f"SSH login OK: {user} from {ip}", "info")
        db_write(
            "INSERT INTO login_events "
            "(timestamp,event_type,username,source_ip,service,success) "
            "VALUES (?,?,?,?,?,1)",
            (now_iso(), "SSH Login Success", user, ip, "SSH")
        )
        return

    # ── Invalid User ─────────────────────────────────
    m = re.search(r'Invalid user (\S+) from ([\d.]+)', line)
    if m:
        user, ip = m.group(1), m.group(2)
        check_brute_force(ip, "SSH")
        add_alert("Invalid User Login Attempt", ip, "SSH:22", "high",
                  detail=f"Unknown user: {user}")
        db_write(
            "INSERT INTO login_events "
            "(timestamp,event_type,username,source_ip,service,success,detail) "
            "VALUES (?,?,?,?,?,0,?)",
            (now_iso(), "Invalid User", user, ip, "SSH", "Unknown username")
        )
        return

    # ── Sudo Command ─────────────────────────────────
    m = re.search(r'sudo.*COMMAND=(.*)', line)
    if m:
        add_alert("Sudo Command Executed", "localhost",
                  m.group(1).strip()[:80], "medium",
                  detail="Privilege elevation via sudo")
        return

    # ── PAM Authentication Failure ───────────────────
    if 'pam_unix' in line and 'failure' in line:
        m2 = re.search(r'user=(\S+)', line)
        user = m2.group(1) if m2 else 'unknown'
        add_log(f"PAM auth failure — user: {user}", "warn")


def watch_log_file(filepath):
    """Tail a log file from the end and process new lines in real time"""
    try:
        with open(filepath, 'r', errors='replace') as f:
            f.seek(0, 2)   # jump to end of file
            add_log(f"Watching log file: {filepath}", "info")
            print(f"[LOG] Watching: {filepath}")
            while running:
                line = f.readline()
                if line:
                    clean = line.strip()
                    if clean:
                        add_log(clean[:300], "info")
                        parse_log_line(line)
                else:
                    time.sleep(0.25)
    except FileNotFoundError:
        add_log(f"Log file not found: {filepath}", "warn")
        print(f"[LOG] Not found (skipped): {filepath}")
    except PermissionError:
        add_log(
            f"Permission denied: {filepath} — "
            "run with: sudo python3 server.py", "warn"
        )
        print(f"[LOG] Permission denied: {filepath}")
        print(f"[LOG] TIP: Run with sudo for full log access")
    except Exception as e:
        add_log(f"Log watcher error {filepath}: {e}", "error")


def start_log_watchers():
    """Start a background thread for each log file"""
    started = 0
    for lf in LOG_FILES:
        if Path(lf).exists():
            t = threading.Thread(target=watch_log_file, args=(lf,), daemon=True)
            t.start()
            started += 1
    if started == 0:
        add_log(
            "No log files found — login alerts will come from simulations. "
            "On Linux: sudo python3 server.py for real auth.log access", "warn"
        )
        print("[LOG] No system log files found")
        print("[LOG] On Linux run: sudo python3 backend/server.py")
        print("[LOG] On Windows: login alerts come from simulations only")

# ══════════════════════════════════════════════════════
#  PERIODIC METRIC SAVER  (saves to DB every 10 seconds)
# ══════════════════════════════════════════════════════
def metric_saver_thread():
    while running:
        try:
            m  = get_metrics()
            nd = get_net_delta()
            db_write(
                "INSERT INTO system_metrics "
                "(timestamp,cpu_percent,mem_percent,disk_percent,"
                "bytes_in,bytes_out,pkts_in,pkts_out,hostname) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    now_iso(),
                    m["cpu"]["percent"],
                    m["memory"]["percent"],
                    m["disk"]["percent"],
                    nd["bytes_in"],
                    nd["bytes_out"],
                    nd["pkts_in"],
                    nd["pkts_out"],
                    m["hostname"],
                )
            )
        except Exception as e:
            pass
        time.sleep(10)

# ══════════════════════════════════════════════════════
#  ATTACK SIMULATION  (for the Simulate Attacks page)
# ══════════════════════════════════════════════════════
async def run_simulation(attack_type, src_ip, tgt_ip, intensity, ws):
    """Stream simulated attack steps to the frontend"""
    SEV_MAP = {"Low": "low", "Medium": "medium", "High": "high", "Critical": "critical"}
    sev     = SEV_MAP.get(intensity, "high")
    t       = lambda: datetime.now().strftime("%H:%M:%S")

    steps = {
        "brute_force": [
            (0.3, f"[{t()}][INIT ] Module: SSH Brute Force | {src_ip} → {tgt_ip}:22"),
            (0.4, f"[{t()}][LOAD ] Wordlist loaded: rockyou.txt (14,344,391 passwords)"),
            (0.5, f"[{t()}][TRY  ] {src_ip} → {tgt_ip}:22 | user=admin  pass=password   → FAIL"),
            (0.5, f"[{t()}][TRY  ] {src_ip} → {tgt_ip}:22 | user=admin  pass=admin123   → FAIL"),
            (0.5, f"[{t()}][TRY  ] {src_ip} → {tgt_ip}:22 | user=root   pass=toor       → FAIL"),
            (0.5, f"[{t()}][TRY  ] {src_ip} → {tgt_ip}:22 | user=root   pass=root123    → FAIL"),
            (0.5, f"[{t()}][TRY  ] {src_ip} → {tgt_ip}:22 | user=admin  pass=qwerty123  → FAIL"),
            (0.4, f"[{t()}][RULE ] ⚠ THRESHOLD: 5 fails/30s — RULE R001 TRIGGERED", "error"),
            (0.3, f"[{t()}][BLOCK] iptables -A INPUT -s {src_ip} -j DROP", "error"),
            (0.2, f"[{t()}][DB   ] Alert saved to database | IP auto-blocked", "error"),
            (0.2, f"[{t()}][DONE ] CRITICAL alert pushed to dashboard", "error"),
        ],
        "port_scan": [
            (0.3, f"[{t()}][INIT ] TCP SYN Scan | {src_ip} → {tgt_ip} | ports 1-65535"),
            (0.3, f"[{t()}][SCAN ] {tgt_ip}:21    → CLOSED  (FTP)"),
            (0.3, f"[{t()}][SCAN ] {tgt_ip}:22    → OPEN    (SSH)"),
            (0.3, f"[{t()}][SCAN ] {tgt_ip}:80    → OPEN    (HTTP)"),
            (0.3, f"[{t()}][SCAN ] {tgt_ip}:443   → OPEN    (HTTPS)"),
            (0.3, f"[{t()}][SCAN ] {tgt_ip}:3306  → OPEN    (MySQL)  ⚠", "warn"),
            (0.3, f"[{t()}][SCAN ] {tgt_ip}:3389  → OPEN    (RDP)    ⚠", "warn"),
            (0.3, f"[{t()}][SCAN ] {tgt_ip}:5432  → OPEN    (Postgres) ⚠", "warn"),
            (0.3, f"[{t()}][SCAN ] {tgt_ip}:6379  → OPEN    (Redis)  ⚠", "warn"),
            (0.4, f"[{t()}][RULE ] ⚠ PORT SCAN: 20+ ports/10s — RULE R002 TRIGGERED", "error"),
            (0.3, f"[{t()}][ALERT] HIGH alert generated | {src_ip} flagged", "error"),
        ],
        "ddos": [
            (0.3, f"[{t()}][INIT ] DDoS Flood | {src_ip} → {tgt_ip}:80"),
            (0.4, f"[{t()}][FLOOD] UDP Flood:  50,000 packets/sec"),
            (0.4, f"[{t()}][FLOOD] ICMP Flood: 15,000 packets/sec"),
            (0.4, f"[{t()}][FLOOD] SYN  Flood: 30,000 packets/sec"),
            (0.4, f"[{t()}][STAT ] Bandwidth consumed: 1.2 Gbps ⚠", "warn"),
            (0.5, f"[{t()}][IMPACT] {tgt_ip} Response time: 4200ms — DEGRADED", "warn"),
            (0.5, f"[{t()}][IMPACT] {tgt_ip} HTTP 503 Service Unavailable", "error"),
            (0.4, f"[{t()}][MITIG] Blackhole route: {src_ip} → null-route applied", "error"),
            (0.3, f"[{t()}][ALERT] CRITICAL — DDoS confirmed from {src_ip}", "error"),
        ],
        "sqli": [
            (0.4, f"[{t()}][INIT ] SQL Injection probe | {src_ip} → {tgt_ip}:80"),
            (0.5, f"[{t()}][PROBE] GET /login?id=1'%20OR%20'1'='1 → HTTP 200 OK ⚠", "warn"),
            (0.5, f"[{t()}][INJECT] Payload: ' OR 1=1 --  → Users table dump"),
            (0.5, f"[{t()}][INJECT] Payload: '; DROP TABLE sessions; --"),
            (0.5, f"[{t()}][INJECT] UNION SELECT table_name FROM information_schema.tables"),
            (0.4, f"[{t()}][DETECT] WAF signature SQL_INJ_001 matched", "error"),
            (0.4, f"[{t()}][BLOCK ] {src_ip} blocked at WAF layer", "error"),
            (0.3, f"[{t()}][ALERT] HIGH — SQL Injection from {src_ip} on {tgt_ip}", "error"),
        ],
        "malware": [
            (0.3, f"[{t()}][INIT ] Malware Dropper simulation on {tgt_ip}"),
            (0.5, f"[{t()}][DROP ] /tmp/.x/payload.sh created | exec bit set ⚠", "warn"),
            (0.5, f"[{t()}][EXEC ] Reverse shell spawned: PID 9999 | bash -i", "warn"),
            (0.5, f"[{t()}][C2   ] ESTABLISHED: {tgt_ip}:4444 → {src_ip}:443", "error"),
            (0.5, f"[{t()}][C2   ] Command recv: id;whoami;cat /etc/passwd", "error"),
            (0.4, f"[{t()}][EXFIL] Sending 4.2MB → {src_ip}:443 (AES encrypted)", "error"),
            (0.4, f"[{t()}][DETECT] Anomalous outbound + C2 beacon pattern matched", "error"),
            (0.3, f"[{t()}][ALERT] CRITICAL — Malware C2 from {tgt_ip} → {src_ip}", "error"),
        ],
        "mitm": [
            (0.4, f"[{t()}][INIT ] ARP Poisoning | Attacker: {src_ip} | Target: {tgt_ip}"),
            (0.5, f"[{t()}][ARP  ] Sending: 192.168.1.1 is-at {src_ip}  (FAKE)", "warn"),
            (0.5, f"[{t()}][ARP  ] Sending: {tgt_ip} is-at {src_ip}  (FAKE)", "warn"),
            (0.5, f"[{t()}][INTERCEPT] Traffic {tgt_ip}↔gateway now routed via {src_ip}", "error"),
            (0.5, f"[{t()}][SNIFF] HTTP creds captured: admin:P@ssw0rd ⚠", "error"),
            (0.4, f"[{t()}][DETECT] ARP table anomaly: duplicate MAC for gateway", "error"),
            (0.3, f"[{t()}][ALERT] HIGH — ARP Spoofing/MITM from {src_ip}", "error"),
        ],
        "ransomware": [
            (0.3, f"[{t()}][INIT ] Ransomware simulation on {tgt_ip}"),
            (0.5, f"[{t()}][ENUM ] Enumerating: \\\\{tgt_ip}\\* — shares found", "warn"),
            (0.5, f"[{t()}][CRYPT] Encrypting: /home/*/Documents/*.docx  AES-256", "error"),
            (0.5, f"[{t()}][CRYPT] Encrypting: /var/data/*.db  AES-256", "error"),
            (0.5, f"[{t()}][CRYPT] Encrypting: /home/*/Photos/*  AES-256", "error"),
            (0.4, f"[{t()}][DROP ] README_HOW_TO_DECRYPT.txt created in all dirs", "error"),
            (0.4, f"[{t()}][C2   ] Bitcoin wallet beacon → {src_ip}:443", "error"),
            (0.3, f"[{t()}][ALERT] CRITICAL — Ransomware activity on {tgt_ip}", "error"),
        ],
        "privilege_escalation": [
            (0.4, f"[{t()}][INIT ] Privilege Escalation attempt on {tgt_ip}"),
            (0.5, f"[{t()}][ENUM ] sudo -l → (ALL) NOPASSWD: /usr/bin/vim  ⚠", "warn"),
            (0.5, f"[{t()}][SUID ] find / -perm -4000 → /usr/bin/python3", "warn"),
            (0.5, f"[{t()}][EXPL ] python3 -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'", "error"),
            (0.4, f"[{t()}][SHELL] Root shell obtained on {tgt_ip} ⚠", "error"),
            (0.4, f"[{t()}][DETECT] UID change 1000→0 detected by HIDS", "error"),
            (0.3, f"[{t()}][ALERT] CRITICAL — Privilege Escalation on {tgt_ip}", "error"),
        ],
    }

    step_list = steps.get(attack_type, [])
    for item in step_list:
        delay = item[0]
        msg   = item[1]
        lvl   = item[2] if len(item) > 2 else "warn"
        await asyncio.sleep(delay)
        try:
            await ws.send(json.dumps({
                "type": "sim_log",
                "msg":  msg,
                "lvl":  lvl
            }))
        except Exception:
            return   # client disconnected

    # Create a real alert from the simulation
    a = add_alert(
        f"Simulated {attack_type.replace('_', ' ').title()} Attack",
        src_ip, tgt_ip, sev,
        detail=f"Simulation | Intensity: {intensity}"
    )
    try:
        await ws.send(json.dumps({"type": "sim_done", "alert": a}))
    except Exception:
        pass

# ══════════════════════════════════════════════════════
#  WEBSOCKET HANDLER
# ══════════════════════════════════════════════════════
async def build_state(full=False):
    """Build the JSON payload sent to browser every 2 seconds"""
    m   = get_metrics()
    nd  = get_net_delta()
    pr  = get_processes()
    cn  = get_connections()

    # Add to network history
    net_history.append({
        "t":   now(),
        "in":  nd["bytes_in"],
        "out": nd["bytes_out"],
        "pi":  nd["pkts_in"],
        "po":  nd["pkts_out"],
    })

    # Get login analysis from DB
    login_stats = db_read(
        "SELECT source_ip, COUNT(*) as attempts, MAX(timestamp) as last_seen "
        "FROM login_events WHERE success=0 "
        "GROUP BY source_ip ORDER BY attempts DESC LIMIT 20"
    )
    recent_logins = db_read(
        "SELECT * FROM login_events ORDER BY id DESC LIMIT 30"
    )

    with lock:
        al = list(alerts)
        lg = list(logs_mem)
        bl = [{"ip": ip, **data} for ip, data in blocked_ips.items()]

    counts = {
        "critical": sum(1 for a in al if a.get("sev") == "critical"),
        "high":     sum(1 for a in al if a.get("sev") == "high"),
        "medium":   sum(1 for a in al if a.get("sev") == "medium"),
        "low":      sum(1 for a in al if a.get("sev") in ("low", "info")),
        "total":    len(al),
        "new":      sum(1 for a in al if a.get("status") == "new"),
    }

    return {
        "type":          "full_state" if full else "update",
        "metrics":       m,
        "net_delta":     nd,
        "net_history":   list(net_history)[-50:],
        "processes":     pr,
        "connections":   cn,
        "alerts":        al[:120],
        "logs":          lg[:80],
        "blocked_ips":   bl,
        "alert_counts":  counts,
        "login_stats":   login_stats,       # real login analysis
        "recent_logins": recent_logins,     # real login events from DB
        "timestamp":     now_iso(),
    }


async def ws_handler(ws, path=None):
    clients.add(ws)
    print(f"[WS] Browser connected: {ws.remote_address}")
    try:
        # Send full state immediately on connect
        await ws.send(json.dumps(await build_state(full=True)))

        # Listen for commands from browser
        async for raw in ws:
            try:
                msg = json.loads(raw)
                cmd = msg.get("type", "")

                if cmd == "get_state":
                    await ws.send(json.dumps(await build_state(full=True)))

                elif cmd == "block_ip":
                    ip     = msg.get("ip", "").strip()
                    reason = msg.get("reason", "Manual Block")
                    if ip:
                        with lock:
                            blocked_ips[ip] = {
                                "reason": reason,
                                "time":   datetime.now().strftime("%H:%M"),
                                "auto":   False,
                            }
                        db_write(
                            "INSERT OR REPLACE INTO blocked_ips "
                            "(ip_address,reason,blocked_at,auto_block,unblocked) "
                            "VALUES (?,?,?,0,0)",
                            (ip, reason, datetime.now().strftime("%H:%M"))
                        )
                        add_alert("IP Manually Blocked", ip, "Firewall", "medium",
                                  detail=f"Reason: {reason}")
                        await ws.send(json.dumps({"type": "blocked", "ip": ip}))

                elif cmd == "unblock_ip":
                    ip = msg.get("ip", "").strip()
                    with lock:
                        blocked_ips.pop(ip, None)
                    db_write(
                        "UPDATE blocked_ips SET unblocked=1 WHERE ip_address=?", (ip,)
                    )
                    add_log(f"IP {ip} unblocked by operator", "info")
                    await ws.send(json.dumps({"type": "unblocked", "ip": ip}))

                elif cmd == "simulate":
                    asyncio.ensure_future(run_simulation(
                        msg.get("attack",    "brute_force"),
                        msg.get("src",       "203.5.113.10"),
                        msg.get("tgt",       "192.168.1.100"),
                        msg.get("intensity", "Medium"),
                        ws
                    ))

                elif cmd == "kill_process":
                    pid = int(msg.get("pid", 0))
                    try:
                        os.kill(pid, signal.SIGTERM)
                        add_log(f"Process PID:{pid} killed by operator", "warn")
                        await ws.send(json.dumps({"type": "proc_killed", "pid": pid}))
                    except Exception as e:
                        await ws.send(json.dumps({"type": "error", "msg": str(e)}))

                elif cmd == "ack_alert":
                    aid = msg.get("id")
                    with lock:
                        for a in alerts:
                            if a.get("id") == aid:
                                a["status"] = "acknowledged"
                                break
                    db_write(
                        "UPDATE alerts SET status='acknowledged' WHERE id=?", (aid,)
                    )

                elif cmd == "clear_alerts":
                    with lock:
                        alerts.clear()

                elif cmd == "get_db_summary":
                    summary = {
                        t: db_read(f"SELECT COUNT(*) as n FROM {t}")[0]["n"]
                        for t in ["alerts", "blocked_ips", "login_events",
                                  "system_metrics", "logs"]
                    }
                    await ws.send(json.dumps({"type": "db_summary", "data": summary}))

            except json.JSONDecodeError:
                pass

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        clients.discard(ws)
        print(f"[WS] Browser disconnected: {ws.remote_address}")


# ── Push updates to all connected browsers every 2s ──
async def broadcast_loop():
    global clients
    while running:
        await asyncio.sleep(2)
        if not clients:
            continue
        try:
            payload = json.dumps(await build_state())
        except Exception as e:
            add_log(f"Broadcast error: {e}", "error")
            continue
        dead = set()
        for ws in list(clients):
            try:
                await ws.send(payload)
            except Exception:
                dead.add(ws)
        clients -= dead

# ══════════════════════════════════════════════════════
#  SIMPLE HTTP SERVER  (serves the dashboard HTML)
# ══════════════════════════════════════════════════════
async def http_handler(reader, writer):
    try:
        data    = await asyncio.wait_for(reader.read(4096), timeout=5)
        request = data.decode("utf-8", errors="replace")
        path    = request.split("\n")[0].split(" ")[1] if request else "/"

        # Path to frontend/index.html  (one level up from backend/)
        html_file = Path(__file__).parent.parent / "frontend" / "index.html"

        if path in ("/", "/index.html") and html_file.exists():
            html = html_file.read_bytes()
            hdr  = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(html)}\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "\r\n"
            )
            writer.write(hdr.encode() + html)
        else:
            writer.write(b"HTTP/1.1 404 Not Found\r\n\r\nNot Found")

        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

# ══════════════════════════════════════════════════════
#  MAIN  — starts everything
# ══════════════════════════════════════════════════════
async def main():
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║         Smart HIDS  —  Real-Time Backend             ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  Dashboard  → http://localhost:{HTTP_PORT}               ║")
    print(f"║  WebSocket  → ws://localhost:{WS_PORT}                ║")
    print(f"║  Database   → {str(DB_PATH)[-40:]}  ║")
    print(f"║  Host       → {platform.node():<38} ║")
    print(f"║  OS         → {platform.system()} {platform.release():<30} ║")
    print(f"║  CPU Cores  → {psutil.cpu_count():<38} ║")
    print(f"║  RAM        → {psutil.virtual_memory().total // 1024**3} GB{'':<36} ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    # Init database
    db_init()

    # Start watching system log files (Linux)
    start_log_watchers()

    # Start background metric saver
    threading.Thread(target=metric_saver_thread, daemon=True).start()

    add_log("Smart HIDS backend started", "info")
    add_log(f"Platform: {platform.system()} {platform.release()}", "info")
    add_log(f"CPU: {psutil.cpu_count()} cores | RAM: {psutil.virtual_memory().total//1024**3}GB", "info")

    # Start HTTP server (serves dashboard HTML)
    http_server = await asyncio.start_server(
        http_handler, "0.0.0.0", HTTP_PORT
    )

    # Start WebSocket server (real-time data)
    ws_server = await websockets.serve(
        ws_handler, "0.0.0.0", WS_PORT,
        ping_interval=20, ping_timeout=30,
        max_size=10_000_000
    )

    print("  ✅  Server running!")
    print(f"  👉  Open your browser → http://localhost:{HTTP_PORT}")
    print()
    print("  Login with any username + password (min 2 characters)")
    print("  Example:  username = admin   password = admin")
    print()
    print("  Press Ctrl+C to stop the server")
    print()

    try:
        await asyncio.gather(
            broadcast_loop(),
            http_server.serve_forever(),
            ws_server.wait_closed(),
        )
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        running = False
        print()
        print("  [!]  HIDS server stopped.")
        print()