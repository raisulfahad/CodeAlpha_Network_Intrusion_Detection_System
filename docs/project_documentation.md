# Project Documentation

## Architecture
Network traffic -> Suricata (af-packet, rules/local.rules) -> `fast.log` + `eve.json`
-> `scripts/auto_block.py` (iptables response) and `scripts/visualize_alerts.py` (chart).

## Detection logic
- **SYN scan (1000001):** 15+ SYN-only packets from one source within 5 s (`threshold type both`).
- **ICMP flood (1000002):** 10+ echo requests from one source within 3 s. Test with `ping -c 15 -i 0.2`.
- **SQLi (1000003):** `UNION` + `SELECT` in the HTTP URI, case-insensitive.

## Response design
Severity-based (<= `--max-severity`), safelist of localhost/own IPs/gateway, dry-run mode, duplicate-rule check, IP validation, no shell invocation.

## Limitations
Signature/threshold detection only; HTTPS payloads are not inspected; spoofed source IPs could cause false blocks, so keep the safelist current and review blocks.

## Evidence to add after your live run
Screenshots of Suricata running, live alerts in `fast.log`, and the real chart in `screenshots/`.
