#!/usr/bin/env python3
"""auto_block.py - tail Suricata eve.json and block high-priority alert sources.

For every alert with severity <= --max-severity (1 = highest in Suricata),
the source IP is dropped with:  iptables -A INPUT -s <ip> -j DROP
Safelisted addresses (localhost, own IPs, default gateway, --safelist) are never blocked.

Usage:
    sudo python3 auto_block.py --dry-run          # log only, change nothing
    sudo python3 auto_block.py --max-severity 2   # really block
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time

EVE_LOG = "/var/log/suricata/eve.json"


def local_addresses():
    """Own IPs and default gateway, so we never lock ourselves out."""
    found = {"127.0.0.1", "::1"}
    for cmd in (["ip", "-o", "addr"], ["ip", "route", "show", "default"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
        except FileNotFoundError:
            continue
        if cmd[1] == "-o":
            found.update(re.findall(r"inet6?\s+([0-9a-fA-F:.]+)/", out))
        else:
            found.update(re.findall(r"via\s+([0-9.]+)", out))
    return found


def follow(path):
    """Yield new lines appended to path (like tail -F, survives log rotation)."""
    f = None
    inode = None
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(1)
            continue
        if f is None or st.st_ino != inode:
            if f:
                f.close()
            f = open(path, "r")
            if inode is None:
                f.seek(0, os.SEEK_END)  # first open: only new events
            inode = st.st_ino
        line = f.readline()
        if line:
            yield line
        else:
            time.sleep(0.5)


def already_blocked(ip):
    return subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
    ).returncode == 0


def block(ip, dry_run):
    if dry_run:
        print(f"[DRY-RUN] would run: iptables -A INPUT -s {ip} -j DROP", flush=True)
        return
    if already_blocked(ip):
        return
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    print(f"[BLOCKED] {ip}", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default=EVE_LOG)
    ap.add_argument("--max-severity", type=int, default=2,
                    help="block alerts with severity <= this value (default 2)")
    ap.add_argument("--safelist", nargs="*", default=[], help="extra IPs that must never be blocked")
    ap.add_argument("--dry-run", action="store_true", help="print actions without running iptables")
    args = ap.parse_args()

    if not args.dry_run and os.geteuid() != 0:
        sys.exit("Run as root (sudo) or use --dry-run.")

    safelist = local_addresses() | set(args.safelist)
    print(f"Watching {args.log} | safelist: {sorted(safelist)}", flush=True)
    seen = set()

    for line in follow(args.log):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") != "alert":
            continue
        alert = ev.get("alert", {})
        if alert.get("severity", 99) > args.max_severity:
            continue
        ip = ev.get("src_ip", "")
        try:
            ipaddress.ip_address(ip)  # validate before it goes near iptables
        except ValueError:
            continue
        if ip in safelist or ip in seen:
            continue
        print(f"[ALERT] {alert.get('signature')} (sev {alert.get('severity')}) from {ip}", flush=True)
        try:
            block(ip, args.dry_run)
            seen.add(ip)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] iptables failed for {ip}: {e}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
