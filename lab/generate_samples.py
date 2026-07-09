#!/usr/bin/env python3
"""
Generate realistic Zeek TSV + Suricata EVE JSON sample logs under lab/samples/,
reproducing the Astra NDR demo attack scenarios. Feed them through a real
sensor:  dotnet run --project src/Astra.Sensor -- replay --log-dir lab/samples

This stands in for running Zeek + Suricata over a PCAP: the output is the same
log format the sensor parses in production.
"""
import json
import os
import random
import time
import uuid

random.seed(7)
OUT = os.path.join(os.path.dirname(__file__), "samples")
os.makedirs(OUT, exist_ok=True)
NOW = time.time()


def zeek_header(path, fields):
    return (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        f"#path\t{path}\n"
        f"#fields\t" + "\t".join(fields) + "\n"
    )


def write_zeek(path, fields, rows):
    with open(os.path.join(OUT, f"{path}.log"), "w") as f:
        f.write(zeek_header(path, fields))
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")


def uid():
    return "C" + uuid.uuid4().hex[:15]


# --- conn.log: internal port scan + benign noise ---
conn_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
               "proto", "service", "duration", "orig_bytes", "resp_bytes",
               "conn_state", "orig_pkts", "resp_pkts"]
conn_rows = []
for i in range(220):
    conn_rows.append([f"{NOW-600+i:.6f}", uid(), "10.50.5.23", random.randint(30000, 60000),
                      f"10.50.5.{random.randint(1,60)}", random.randint(1, 1024),
                      "tcp", "-", "0.001", 60, 40, "S0", 2, 1])
# large exfil upload
for i in range(20):
    conn_rows.append([f"{NOW-300+i*8:.6f}", uid(), "10.50.9.15", random.randint(30000, 60000),
                      "198.51.100.9", 443, "tcp", "ssl", "5.0", 6000000, 40000, "SF", 4200, 300])
# benign
for i in range(60):
    conn_rows.append([f"{NOW-random.randint(0,3600):.6f}", uid(), f"10.50.{random.randint(1,20)}.{random.randint(2,250)}",
                      random.randint(30000, 60000), random.choice(["93.184.216.34", "142.250.72.14"]),
                      443, "tcp", "ssl", "1.2", random.randint(500, 5000), random.randint(5000, 50000), "SF", 20, 30])
write_zeek("conn", conn_fields, conn_rows)

# --- dns.log: DNS tunneling ---
dns_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
              "proto", "query", "qtype_name", "rcode_name", "answers"]
dns_rows = []
for i in range(80):
    label = uuid.uuid4().hex + uuid.uuid4().hex[:20]
    q = f"{label[:52]}.tunnel-c2-demo.net"
    dns_rows.append([f"{NOW-900+i*8:.6f}", uid(), "10.50.7.44", random.randint(30000, 60000),
                     "10.50.0.53", 53, "udp", q, "TXT" if i % 2 == 0 else "A", "NOERROR", "-"])
write_zeek("dns", dns_fields, dns_rows)

# --- ssl.log: HTTPS beaconing ---
ssl_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
              "proto", "version", "cipher", "server_name", "subject", "issuer", "ja3", "ja3s"]
ssl_rows = []
for i in range(40):
    jitter = random.uniform(-1, 1)
    ssl_rows.append([f"{NOW-1200+i*30+jitter:.6f}", uid(), "10.50.9.15", random.randint(30000, 60000),
                     "203.0.113.66", 443, "tcp", "TLSv12",
                     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "cdn-metrics.example-c2.net",
                     "CN=cdn-metrics.example-c2.net", "CN=Lets Encrypt", "6f1c2d3e4a5b6c7d", "abc123"])
write_zeek("ssl", ssl_fields, ssl_rows)

# --- smb_files.log: admin-share lateral movement ---
smb_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
              "action", "path", "name", "size"]
smb_rows = []
for i in range(6):
    smb_rows.append([f"{NOW-450+i*15:.6f}", uid(), "10.50.9.15", random.randint(30000, 60000),
                     f"10.60.0.{20+i}", 445, "SMB::FILE_WRITE",
                     "ADMIN$", "\\Windows\\Temp\\svc.exe", 250000])
write_zeek("smb_files", smb_fields, smb_rows)

# --- kerberos.log: brute force + success ---
krb_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
              "client", "service", "success", "error_msg"]
krb_rows = []
for i in range(14):
    krb_rows.append([f"{NOW-800+i*20:.6f}", uid(), "10.50.9.15", random.randint(30000, 60000),
                     "10.60.0.10", 88, "svc-backup", "cifs/dc01-admin", "F", "PREAUTH_FAILED"])
krb_rows.append([f"{NOW-490:.6f}", uid(), "10.50.9.15", random.randint(30000, 60000),
                 "10.60.0.10", 88, "svc-backup", "cifs/dc01-admin", "T", "-"])
write_zeek("kerberos", krb_fields, krb_rows)

# --- Suricata eve.json: alerts + tls corroboration ---
eve_lines = []
def eve_ts(offset):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(NOW + offset))

# high-severity C2 alert against the beaconing host
for i in range(3):
    eve_lines.append(json.dumps({
        "timestamp": eve_ts(-1100 + i * 200), "event_type": "alert", "flow_id": random.randint(1, 10**15),
        "src_ip": "10.50.9.15", "src_port": 44100 + i, "dest_ip": "203.0.113.66", "dest_port": 443, "proto": "TCP",
        "alert": {"signature": "ET MALWARE Observed Malicious SSL Cert (C2)", "signature_id": 2028371,
                  "rev": 3, "category": "A Network Trojan was Detected", "severity": 1}}))
# a medium policy alert
eve_lines.append(json.dumps({
    "timestamp": eve_ts(-800), "event_type": "alert", "flow_id": random.randint(1, 10**15),
    "src_ip": "10.50.7.44", "src_port": 51000, "dest_ip": "10.50.0.53", "dest_port": 53, "proto": "UDP",
    "alert": {"signature": "ET POLICY DNS Query for Suspicious TLD", "signature_id": 2013028,
              "rev": 6, "category": "Potentially Bad Traffic", "severity": 2}}))
with open(os.path.join(OUT, "eve.json"), "w") as f:
    f.write("\n".join(eve_lines) + "\n")

print(f"Wrote sample logs to {OUT}/")
for name in sorted(os.listdir(OUT)):
    print("  ", name)
