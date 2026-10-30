# 3. Python Log Parser & Security Reporter

**Type:** Hands-on coding project — a working tool, not just a write-up
**Tools:** Python, regex
**Skills demonstrated:** Log parsing, pattern matching, reporting, turning raw logs into an actionable finding

## What it does

`log_parser.py` reads a Linux auth-style log and produces a short security report:

- Total lines, failed logins, and successful logins
- Failed logins by source IP and by username
- Successful logins by user and IP
- Flags any IP with repeated failures (default threshold: 5) and recommends next steps

## Run it

```bash
python3 log_parser.py sample_auth.log
python3 log_parser.py sample_auth.log --threshold 5
```

## Sample output (from the synthetic sample log)

```
=== Log Parser Security Report ===
Lines processed: 12
Failed logins:   8
Successful logins: 2

Failed logins by IP:
  203.0.113.45: 6  <-- FLAGGED: repeated failures
  198.51.100.23: 2

Failed logins by user:
  admin: 5
  test: 2
  root: 1

Successful logins (user @ IP):
  yankuba @ 192.0.2.10: 2

Recommendation: review / blocklist flagged IPs: 203.0.113.45
```

## Important notes

- The sample log is **synthetic data only**, using documentation IP ranges (RFC 5737). It is not a real system log and does not describe a real incident.
- The script is deliberately simple and readable: a hiring manager or reviewer can follow the regex, the counters, and the report logic in one file.
- In a real investigation, a flagged IP is a lead, not a verdict. The next steps are to check that IP in other logs, confirm whether any login succeeded after the failures, and reset any affected accounts.

## Possible extensions

- Parse timestamps and report failures per hour, to spot brute-force bursts
- Add JSON output for ingestion into Splunk or another SIEM
- Add allowlisting for known internal IPs, so routine admin failures do not flag
