#!/usr/bin/env python3
"""
Python Log Parser & Security Reporter
=====================================

Parses Linux auth-style logs, counts failed logins by user and source IP,
flags IPs with repeated failures, and prints a short security summary.

Usage:
    python3 log_parser.py sample_auth.log
    python3 log_parser.py sample_auth.log --threshold 5

The sample log in this folder is SYNTHETIC data, created for demonstration.
It is not a real system log and does not describe a real incident.
"""

import argparse
import re
import sys
from collections import Counter, defaultdict

# Example: "Oct 29 10:15:32 server sshd[1234]: Failed password for admin from 203.0.113.45 port 22 ssh2"
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)


def parse_log(path):
    failed_by_ip = Counter()
    failed_by_user = Counter()
    accepted = Counter()
    total_lines = 0

    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            m = FAILED_RE.search(line)
            if m:
                user, ip = m.groups()
                failed_by_user[user] += 1
                failed_by_ip[ip] += 1
                continue
            m = ACCEPTED_RE.search(line)
            if m:
                user, ip = m.groups()
                accepted[(user, ip)] += 1

    return total_lines, failed_by_ip, failed_by_user, accepted


def main():
    parser = argparse.ArgumentParser(description="Parse auth logs and report failed logins.")
    parser.add_argument("logfile", help="Path to the auth log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed-login count above which an IP is flagged (default: 5)")
    args = parser.parse_args()

    try:
        total, failed_by_ip, failed_by_user, accepted = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        return 1

    total_failed = sum(failed_by_ip.values())
    total_accepted = sum(accepted.values())

    print("=== Log Parser Security Report ===")
    print(f"Lines processed: {total}")
    print(f"Failed logins:   {total_failed}")
    print(f"Successful logins: {total_accepted}")
    print()
    print("Failed logins by IP:")
    for ip, count in failed_by_ip.most_common():
        flag = "  <-- FLAGGED: repeated failures" if count >= args.threshold else ""
        print(f"  {ip}: {count}{flag}")
    print()
    print("Failed logins by user:")
    for user, count in failed_by_user.most_common():
        print(f"  {user}: {count}")
    print()
    print("Successful logins (user @ IP):")
    for (user, ip), count in accepted.most_common():
        print(f"  {user} @ {ip}: {count}")
    print()
    flagged = [ip for ip, c in failed_by_ip.items() if c >= args.threshold]
    if flagged:
        print(f"Recommendation: review / blocklist flagged IPs: {', '.join(flagged)}")
        print("Next steps: check those IPs in other logs, confirm whether any")
        print("login succeeded after the failures, and reset any affected accounts.")
    else:
        print("No IPs met the flag threshold. Continue routine monitoring.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
