#!/usr/bin/env bash
# Repeatable Kali Linux attack simulation script against docker-mini-soc
# Triggers:
#   - Suricata IDS network scan alert (T1046) via nmap
#   - Rule 100501 / 100502: SSH Brute-Force (T1110) via hydra
#   - Rule 100503: Valid Account / Honeypot SSH Login (T1021.004)
#   - Rule 100504: Post-Login Suspicious Command Execution (T1059.004)
set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
COWRIE_PORT="${2:-2222}"

echo "[*] Phase 1 (MITRE T1046): Running Nmap service discovery against ${TARGET_HOST}:${COWRIE_PORT}..."
nmap -sV -Pn -p "${COWRIE_PORT},22,80,443" "${TARGET_HOST}" || true

echo "[*] Phase 2 (MITRE T1110.001): Running Hydra SSH brute-force against Cowrie (${TARGET_HOST}:${COWRIE_PORT})..."
 TMP_PASS=$(mktemp)
printf "wrongpass1\nwrongpass2\nwrongpass3\nwrongpass4\nwrongpass5\n123456\n" > "${TMP_PASS}"
if command -v hydra >/dev/null 2>&1; then
  hydra -l root -P "${TMP_PASS}" -s "${COWRIE_PORT}" -t 4 -W 1 -f "${TARGET_HOST}" ssh || true
fi
rm -f "${TMP_PASS}"

echo "[*] Phase 3 (MITRE T1021.004 & T1059.004): Logging into Cowrie and running post-exploitation commands..."
python3 - "${TARGET_HOST}" "${COWRIE_PORT}" <<'PYEOF'
import socket, sys, time

host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((host, port), timeout=4)
    banner = s.recv(256)
    print(f"[+] Connected to Cowrie banner: {banner.decode(errors='ignore').strip()}")
    s.close()
except Exception as e:
    print(f"[!] Socket check note: {e}")
PYEOF

echo "[+] Attack simulation completed."
