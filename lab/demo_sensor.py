#!/usr/bin/env python3
"""
Astra NDR - demo sensor simulator.

Exercises the real central-brain ingestion API (heartbeat + event batches) the
same way a field sensor would: it authenticates with the shared sensor token,
sends a heartbeat, then replays several attack scenarios as normalized events.

This is lab tooling. All traffic is synthetic and targets RFC1918 / TEST-NET
(RFC5737) addresses only.

Usage:
    python3 lab/demo_sensor.py --api http://localhost:5170 \
        --token dev-sensor-token-change-me

The scenarios mirror the built-in seed generator so the detection, scoring and
correlation engines light up even on a fresh database.
"""
import argparse
import json
import random
import urllib.request
import uuid
from datetime import datetime, timezone, timedelta

SENSOR_ID = "44444444-4444-4444-4444-444444444444"
SENSOR_NAME = "sensor-lab-01"


def now_iso(offset_sec=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_sec)).isoformat()


def post(url, token, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "X-Astra-Sensor-Token": token})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, resp.read().decode()


def event(category, proto, app, src, dst, sport=None, dport=None,
          bytes_in=0, bytes_out=0, packets_in=0, packets_out=0, fields=None, offset=0):
    return {
        "timestamp": now_iso(offset),
        "observedTime": now_iso(offset),
        "category": category,
        "protocol": proto,
        "applicationProtocol": app,
        "sourceIp": src,
        "destinationIp": dst,
        "sourcePort": sport,
        "destinationPort": dport,
        "hostname": None,
        "username": None,
        "bytesIn": bytes_in,
        "bytesOut": bytes_out,
        "packetsIn": packets_in,
        "packetsOut": packets_out,
        "durationMs": None,
        "fields": fields or {},
    }


def build_events():
    events = []

    # Scenario 1: internal port scan
    scanner = "10.30.5.23"
    for i in range(180):
        dst = f"10.30.5.{random.randint(1, 60)}"
        events.append(event("network_connection", "tcp", "-", scanner, dst,
                            dport=random.randint(1, 1024), bytes_out=60, bytes_in=40,
                            packets_out=2, packets_in=1, offset=-600 + i))

    # Scenario 2: DNS tunneling
    dns_host = "10.30.7.44"
    for i in range(70):
        label = uuid.uuid4().hex + uuid.uuid4().hex[:20]
        q = f"{label[:52]}.exfil-lab-demo.net"
        events.append(event("dns", "udp", "dns", dns_host, "10.30.0.53", dport=53,
                            bytes_out=len(q),
                            fields={"query": q, "query_type": "TXT" if i % 2 == 0 else "A",
                                    "rcode": "NOERROR"},
                            offset=-900 + i * 8))

    # Scenario 3: HTTPS beaconing every ~30s
    beacon = "10.30.9.15"
    c2 = "203.0.113.77"
    for i in range(35):
        events.append(event("tls", "tcp", "tls", beacon, c2, dport=443,
                            bytes_out=1200 + random.randint(0, 300),
                            bytes_in=800, packets_out=6, packets_in=5,
                            fields={"sni": "metrics.lab-c2.net", "tls_version": "TLSv1.2",
                                    "ja3": "ja3:labfingerprint"},
                            offset=-1200 + i * 30 + random.randint(-1, 1)))

    # Scenario 4: brute force + success (Kerberos)
    acct = "svc-lab-backup"
    for i in range(14):
        events.append(event("kerberos", "tcp", "kerberos", beacon, "10.40.0.10", dport=88,
                            fields={"auth_protocol": "kerberos", "target_service": "cifs/dc-lab",
                                    "result": "failure", "failure_reason": "PREAUTH_FAILED",
                                    "is_privileged": "true", "account": acct},
                            offset=-800 + i * 20))
    events.append(event("kerberos", "tcp", "kerberos", beacon, "10.40.0.10", dport=88,
                        fields={"auth_protocol": "kerberos", "target_service": "cifs/dc-lab",
                                "result": "success", "is_privileged": "true", "account": acct},
                        offset=-490))

    # Scenario 5: admin-share lateral movement
    for i in range(6):
        target = f"10.40.0.{20 + i}"
        events.append(event("smb_file", "tcp", "smb", beacon, target, dport=445,
                            bytes_out=250000,
                            fields={"share": "ADMIN$", "path": "\\Windows\\Temp\\svc.exe",
                                    "named_pipe": "svcctl", "operation": "write",
                                    "is_admin_share": "true"},
                            offset=-450 + i * 15))

    # Scenario 6: large exfil upload to rare destination
    for i in range(20):
        events.append(event("network_connection", "tcp", "tls", beacon, "198.51.100.9",
                            dport=443, bytes_out=6_000_000, bytes_in=40_000,
                            packets_out=4200, packets_in=300, offset=-300 + i * 8))

    return events


def main():
    ap = argparse.ArgumentParser(description="Astra NDR demo sensor simulator")
    ap.add_argument("--api", default="http://localhost:5170")
    ap.add_argument("--token", default="dev-sensor-token-change-me")
    ap.add_argument("--batch", type=int, default=500)
    args = ap.parse_args()

    # 1) heartbeat
    hb = {
        "sensorId": SENSOR_ID, "sensorName": SENSOR_NAME, "version": "1.0.0",
        "cpuPercent": 24.0, "memoryPercent": 38.0, "diskPercent": 52.0,
        "interfaceUp": True, "packetDropPercent": 0.2, "eventsPerSecond": 1300.0,
        "bufferedEvents": 0, "zeekRunning": True, "suricataRunning": True, "errors": [],
    }
    status, body = post(f"{args.api}/api/ingest/heartbeat", args.token, hb)
    print(f"heartbeat -> {status}: {body}")

    # 2) event batches
    events = build_events()
    total_accepted = 0
    for i in range(0, len(events), args.batch):
        chunk = events[i:i + args.batch]
        req = {"sensorId": SENSOR_ID, "sensorName": SENSOR_NAME, "events": chunk}
        status, body = post(f"{args.api}/api/ingest/events", args.token, req)
        resp = json.loads(body)
        total_accepted += resp.get("accepted", 0)
        print(f"batch {i // args.batch} -> {status}: accepted={resp.get('accepted')} "
              f"rejected={resp.get('rejected')}")

    print(f"\nSent {len(events)} events ({total_accepted} accepted).")
    print("Detections run on the server's analysis interval (default 15s).")
    print(f"Open the console and check the dashboard / detections for lab activity.")


if __name__ == "__main__":
    main()
