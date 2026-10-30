# 1. SOC Log Analysis with Splunk

**Type:** Hands-on lab project (TryHackMe / Splunk lab environments, including Boss of the SOC style work)
**Tools:** Splunk, SPL (Search Processing Language)
**Skills demonstrated:** Alert triage, log correlation, timeline building, investigation documentation

## Objective

Triage a security alert, investigate it through logs, decide whether it is a true positive, false positive, or benign, and document findings and recommended next steps — the core daily work of a SOC analyst.

## Investigation method

1. **Triage the alert**
   - What triggered it? Which host, user, and time window?
   - What is the severity, and what asset is affected?
2. **Gather context**
   - Authentication logs: successful and failed logons, unusual times, new source IPs
   - Process and endpoint logs: unexpected processes, scheduled tasks, PowerShell use
   - Network logs: DNS lookups, outbound connections, data volume
   - Web / proxy logs: unusual user agents, rare domains, large downloads
3. **Build a timeline**
   - Put events in time order. A single event rarely tells the story; a sequence does.
4. **Correlate**
   - Does the same user, host, IP, or file hash appear in other logs?
   - Does the activity match a known pattern (brute force, credential use, lateral movement)?
5. **Conclude and recommend**
   - True positive / false positive / benign, with evidence for each claim
   - Containment, eradication, and follow-up steps, if needed

## Useful SPL patterns

```spl
# Failed logons by user and source IP
index=* EventCode=4625
| stats count by user, src_ip
| sort - count

# Successful logons outside normal hours, by user
index=* EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count by user, src_ip, hour

# Rare processes on a host
index=* sourcetype="WinEventLog:*"
| stats count by host, process_name
| sort count
```

## Sample investigation write-up structure

- **Alert:** [what fired, when, severity]
- **Assets / users involved:** [host, user, IP]
- **Timeline:** [time-ordered events, with sources]
- **Evidence:** [log excerpts and query results that support each point]
- **Assessment:** [true positive / false positive / benign, and why]
- **Recommended actions:** [contain, investigate further, close, monitor]
- **Lessons learned:** [what to detect better next time]

## What I learned

- Do not close an alert on one log line. Corroborate across authentication, endpoint, and network logs.
- A timeline is more persuasive than a list of events.
- Documenting the reasoning matters as much as the conclusion — the next analyst, and a hiring manager, should be able to follow it.
