#!/usr/bin/env python3
"""SSH Brute-Force Detector.

Reads a Linux auth log (e.g. /var/log/auth.log) and reports IP addresses
with many failed SSH logins - a typical sign of a brute-force attack
against YOUR server. Can export a list of suggested firewall rules.
"""
import argparse
import re
import sys
from collections import Counter, defaultdict

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")


def parse(lines):
    failed = Counter()
    users = defaultdict(set)
    accepted = defaultdict(set)
    for line in lines:
        m = FAILED_RE.search(line) or INVALID_RE.search(line)
        if m and "Failed password" in line:
            failed[m["ip"]] += 1
            users[m["ip"]].add(m["user"])
            continue
        m = ACCEPTED_RE.search(line)
        if m:
            accepted[m["ip"]].add(m["user"])
    return failed, users, accepted


def report(failed, users, accepted, threshold):
    suspects = [(ip, n) for ip, n in failed.most_common() if n >= threshold]
    if not suspects:
        print(f"[OK] No IP with >= {threshold} failed logins.")
        return suspects
    print(f"{'IP':<40}{'FAILS':>6}  USERS TRIED")
    print("-" * 70)
    for ip, n in suspects:
        tried = ", ".join(sorted(users[ip]))[:40]
        print(f"{ip:<40}{n:>6}  {tried}")
        if ip in accepted:
            print(f"   !!! WARNING: {ip} also logged in successfully as "
                  f"{', '.join(sorted(accepted[ip]))} - check this account!")
    return suspects


def main():
    p = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth logs")
    p.add_argument("logfile", nargs="?", default="/var/log/auth.log")
    p.add_argument("-t", "--threshold", type=int, default=5, help="min failures to flag")
    p.add_argument("--ufw", action="store_true", help="print suggested ufw block rules")
    args = p.parse_args()
    try:
        with open(args.logfile, errors="ignore") as f:
            failed, users, accepted = parse(f)
    except PermissionError:
        sys.exit("Permission denied - try with sudo.")
    except FileNotFoundError:
        sys.exit(f"File not found: {args.logfile}")
    suspects = report(failed, users, accepted, args.threshold)
    if args.ufw and suspects:
        print("\n# Suggested rules (review before applying!):")
        for ip, _ in suspects:
            print(f"sudo ufw deny from {ip}")


if __name__ == "__main__":
    main()
