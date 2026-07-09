# Astra NDR — Lab & Demo

Two ways to get realistic activity into the console.

## 1. Built-in seed (zero setup)

On first start with `ASTRA_SEED_DEMO=true` (default), the brain seeds three sensors with
health and generates synthetic telemetry reproducing six attack scenarios, then runs one
analysis pass. The dashboard, entity queue, detections, incidents and sensor health are
populated immediately. Set `ASTRA_SEED_DEMO=false` to start empty.

## 1b. Real sensor over Zeek/Suricata logs (recommended)

The `Astra.Sensor` agent parses **real Zeek TSV + Suricata EVE JSON** and posts to the
brain — the same path a production sensor uses. Generate sample logs (stand-ins for
Zeek/Suricata output over a PCAP) and replay them:

```bash
python3 lab/generate_samples.py                 # writes lab/samples/*.log + eve.json
dotnet run --project src/Astra.Sensor -- replay --log-dir lab/samples
```

Replay rebases timestamps to now by default, so detections fire immediately. This path
also produces **Suricata-driven IDS signature detections** that correlate with the
behavioral ones on the same host, plus a real AI investigation summary on the entity
page.

## 2. Lab sensor simulator (exercises the real ingest API)

[`lab/demo_sensor.py`](../lab/demo_sensor.py) authenticates as a sensor and replays the
scenarios over HTTP — the exact path a field sensor uses.

```bash
python3 lab/demo_sensor.py \
    --api http://localhost:5170 \
    --token dev-sensor-token-change-me
```

It sends a heartbeat (auto-registers `sensor-lab-01`) then event batches, and reports how
many were accepted. Detections appear after the next analysis cycle (default 15 s).

## Scenarios and the detections they trigger

| Scenario | Traffic | Detection |
|----------|---------|-----------|
| Internal port scan | one host → many ports/hosts | `recon.internal_port_scan` (T1046) |
| DNS tunneling | long/TXT queries to one domain | `c2.dns_tunnel_indicators` (T1071.004) |
| HTTPS beaconing | periodic TLS to external IP | `c2.beaconing` (T1071.001) |
| Brute force + success | Kerberos failures then success | `cred.bruteforce_then_success` (T1110) |
| Admin-share lateral | C$/ADMIN$ writes to many hosts | `lateral.admin_share_access` (T1021.002) |
| Large exfil upload | upload-heavy flow to rare dest | `exfil.large_upload_rare_destination` (T1048) |

Because several scenarios share the primary host `10.x.9.15`, the **correlation engine**
raises an incident with an escalated attack profile (e.g. *IntrusionWithExfiltration* /
*RansomwareStaging*) and computes blast radius across the involved entities.

## Full lab topology (roadmap)

The target lab (Phase 2+) adds real capture: an Ubuntu sensor running Zeek + Suricata, a
Kali attacker, Windows/Linux victims, an optional domain controller, and optional
cloud/SaaS log simulators — plus PCAP replay of the same scenarios. The Python simulator
here provides the equivalent detections today without requiring that infrastructure.

## Attack-simulation catalog

The simulator covers scan/slow-scan, DNS tunneling & TXT exfil, HTTP/HTTPS beaconing,
direct-IP HTTPS, rare-destination C2, SMB/RDP/SSH lateral movement, suspicious remote
execution, password spray, success-after-failures, large upload, ransomware-like SMB
writes, and threat-intel IOC matches as the detection catalog fills out across phases.
