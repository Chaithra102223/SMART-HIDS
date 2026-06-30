"""
Smart HIDS — Attack Test Script
Generates REAL network activity to trigger real alerts in the dashboard.

File: scripts/attack_test.py
Run: python3 scripts/attack_test.py

WARNING: Only run on your OWN machine / local network.
"""

import socket
import subprocess
import threading
import time
import os
import sys
import platform

TARGET = "127.0.0.1"   # ← change to your target IP (keep 127.0.0.1 for local test)
MY_IP  = "127.0.0.1"

print("="*55)
print("  Smart HIDS — Real Attack Test Script")
print("="*55)
print(f"  Target : {TARGET}")
print(f"  Platform: {platform.system()}")
print()
print("  Each test generates REAL network traffic")
print("  that the HIDS backend will detect.")
print("="*55)

# ── TEST 1: Rapid TCP Connection (port scan simulation) ─
def test_port_scan():
    print("\n[TEST 1] Port Scan — rapid TCP SYN to common ports")
    ports = [21,22,23,25,80,443,3306,3389,5432,6379,8080,8443,9200,27017]
    found = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((TARGET, port))
            status = "OPEN" if result == 0 else "CLOSED"
            if result == 0:
                found.append(port)
            print(f"  {TARGET}:{port:<6} {status}")
            s.close()
        except Exception as e:
            print(f"  {TARGET}:{port:<6} ERROR ({e})")
        time.sleep(0.05)
    print(f"\n  [+] Open ports found: {found}")
    print("  [+] This should trigger a PORT SCAN alert in HIDS")

# ── TEST 2: Failed SSH Logins (brute force simulation) ──
def test_brute_force():
    print("\n[TEST 2] SSH Brute Force — rapid failed login attempts")
    print("  (Sending fake SSH auth packets to port 22)")
    passwords = ["password","admin123","root123","qwerty","letmein",
                 "123456","password1","admin","root","toor"]
    for i, pw in enumerate(passwords):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            r = s.connect_ex((TARGET, 22))
            if r == 0:
                # Send SSH banner probe
                s.send(b"SSH-2.0-OpenSSH_8.0\r\n")
                try: s.recv(256)
                except: pass
            s.close()
            print(f"  Attempt {i+1}: user=admin pass={pw} → FAIL (expected)")
        except Exception as e:
            print(f"  Attempt {i+1}: error ({e})")
        time.sleep(0.2)
    print("\n  [+] 10 connection attempts made")
    print("  [+] If SSH is running, this triggers BRUTE FORCE alert")
    print("  [+] Check auth.log: sudo tail -f /var/log/auth.log")

# ── TEST 3: High UDP Traffic (DDoS simulation) ──────────
def test_traffic_flood():
    print("\n[TEST 3] Traffic Flood — burst UDP packets")
    print("  (Sending 2000 UDP packets to trigger network spike alert)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"X" * 1024
        count = 0
        start = time.time()
        while time.time() - start < 3:
            try:
                s.sendto(payload, (TARGET, 9999))
                count += 1
            except Exception:
                break
        s.close()
        print(f"  [+] Sent {count} UDP packets in 3 seconds")
        print("  [+] Check HIDS Network Traffic page for spike")
    except Exception as e:
        print(f"  [!] Error: {e}")

# ── TEST 4: Suspicious Port Connection ─────────────────
def test_suspicious_port():
    print("\n[TEST 4] Suspicious Port — attempt connection to port 4444")
    print("  (Port 4444 = common reverse shell / Metasploit port)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((TARGET, 4444))
        print(f"  Port 4444: {'OPEN' if result==0 else 'CLOSED/REFUSED'}")
        s.close()
    except Exception as e:
        print(f"  Port 4444: {e}")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((TARGET, 1337))
        print(f"  Port 1337: {'OPEN' if result==0 else 'CLOSED/REFUSED'}")
        s.close()
    except Exception as e:
        print(f"  Port 1337: {e}")
    print("  [+] These connections appear in HIDS Connections page as HIGH THREAT")

# ── TEST 5: Trigger auth.log entries (Linux only) ──────
def test_auth_log():
    print("\n[TEST 5] Auth Log Trigger — failed SSH via system command")
    print("  (Creates real /var/log/auth.log entries)")
    if platform.system() != "Linux":
        print("  [!] Skipped — Linux only (WSL also works)")
        return
    
    print("  Running: ssh -o BatchMode=yes -o ConnectTimeout=2 baduser@localhost")
    for i in range(6):
        try:
            result = subprocess.run(
                ["ssh", "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=2",
                 "-o", "StrictHostKeyChecking=no",
                 f"testuser{i}@{TARGET}", "exit"],
                capture_output=True, timeout=3
            )
            print(f"  SSH attempt {i+1}: returned {result.returncode}")
        except FileNotFoundError:
            print("  [!] ssh not found — install: sudo apt install openssh-client")
            break
        except Exception as e:
            print(f"  SSH attempt {i+1}: {e}")
        time.sleep(0.5)
    print("  [+] Check HIDS: should show BRUTE FORCE CRITICAL alert")
    print("  [+] Auth.log: sudo tail -20 /var/log/auth.log")

# ── TEST 6: Write suspicious process name (Linux only) ──
def test_suspicious_process():
    print("\n[TEST 6] Suspicious Process — create process with bad name")
    if platform.system() != "Linux":
        print("  [!] Skipped — Linux only")
        return
    print("  Creating a process named 'ncat' (mimics netcat)...")
    try:
        # Create a harmless script with suspicious name in /tmp
        script = "/tmp/ncat_test.sh"
        with open(script, "w") as f:
            f.write("#!/bin/bash\nsleep 8\n")
        os.chmod(script, 0o755)
        proc = subprocess.Popen(["/bin/bash", "-c",
            f"exec -a ncat {script}"], stdout=subprocess.DEVNULL)
        print(f"  [+] Process 'ncat' started with PID: {proc.pid}")
        print("  [+] HIDS should detect it in Processes page within 5 seconds")
        print("  [+] Check for CRITICAL alert: Suspicious Process: ncat")
        time.sleep(6)
        proc.terminate()
        print("  [+] Process terminated")
    except Exception as e:
        print(f"  [!] Error: {e}")

# ── MAIN MENU ───────────────────────────────────────────
def main():
    print("\nSelect tests to run:")
    print("  1) Port Scan (triggers PORT SCAN alert)")
    print("  2) Brute Force SSH attempts (triggers BRUTE FORCE alert)")
    print("  3) Traffic Flood/UDP burst (triggers NETWORK SPIKE alert)")
    print("  4) Suspicious Port connect (triggers CONNECTION THREAT)")
    print("  5) Auth.log SSH fails (Linux only — triggers real log alert)")
    print("  6) Suspicious Process (Linux only — triggers PROCESS alert)")
    print("  A) Run ALL tests")
    print("  Q) Quit")
    print()

    choice = input("Enter choice [1-6 / A / Q]: ").strip().upper()

    tests = {
        "1": test_port_scan,
        "2": test_brute_force,
        "3": test_traffic_flood,
        "4": test_suspicious_port,
        "5": test_auth_log,
        "6": test_suspicious_process,
    }

    if choice == "Q":
        print("Exiting.")
        return
    elif choice == "A":
        for fn in tests.values():
            fn()
            print()
    elif choice in tests:
        tests[choice]()
    else:
        print("Invalid choice.")
        return

    print("\n" + "="*55)
    print("  Tests complete!")
    print("  Open http://localhost:8080 to see the alerts")
    print("="*55)

if __name__ == "__main__":
    main()
