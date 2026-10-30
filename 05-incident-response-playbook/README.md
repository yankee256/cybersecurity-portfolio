# 5. Incident Response Playbook

**Type:** Hands-on lab project / procedural documentation
**Tools:** Incident response lifecycle, log analysis, containment checklists
**Skills demonstrated:** Structured response, documentation, communication under pressure

## Objective

Provide a clear, usable playbook for the three incident types a junior analyst is most likely to face first: phishing, malware, and unauthorised access. The goal is not to memorise steps, but to respond in order, preserve evidence, and communicate clearly.

## Lifecycle used

Preparation → Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned

## Playbook 1: Phishing

1. **Detect & triage**
   - Who received it? Did anyone click, open an attachment, or enter credentials?
   - Preserve the original message headers and links — do not forward it around casually.
2. **Contain**
   - If credentials were entered, force a password reset and revoke sessions.
   - Block the sender domain / URL at email and web gateways, if authorised.
   - Search mailboxes for other recipients of the same message.
3. **Analyse**
   - What did the link / attachment do? Check logs, endpoint alerts, and DNS.
   - Was there lateral movement or data access after the click?
4. **Eradicate & recover**
   - Remove malicious mail, clean affected endpoints, restore from known-good state if needed.
   - Monitor the affected accounts closely after recovery.
5. **Lessons learned**
   - Report the phish, update filters, and note what user training would have helped.

## Playbook 2: Malware on a host

1. Isolate the host from the network (do not power it off immediately — volatile evidence may be lost).
2. Preserve logs and a forensic image, if procedure requires it.
3. Identify the malware family, persistence mechanism, and affected files/processes.
4. Remove persistence, clean or reimage the host, and change credentials used on it.
5. Verify with a clean scan, monitor for reinfection, and document the full timeline.

## Playbook 3: Unauthorised access

1. Confirm the access: which account, from where, when, and what was accessed?
2. Disable / lock the account and revoke active sessions immediately.
3. Review authentication logs for other logins from the same source.
4. Check for privilege changes, new accounts, and data access or exfiltration.
5. Reset affected credentials, review access controls, and tighten monitoring on that account and system.

## Documentation template for every incident

- **Incident ID / date / reporter:**
- **Summary (one paragraph):**
- **Timeline:**
- **Systems / users affected:**
- **Evidence collected:**
- **Actions taken (with times):**
- **Root cause:**
- **Recovery status:**
- **Lessons learned / follow-up actions:**

## What I learned

- Containment before cleanup. Cleaning too early can destroy evidence and let an attacker return.
- Write as you go. A timeline reconstructed from memory after the fact is unreliable.
- Communication is part of response: who needs to know, what do they need to decide, and when?
