# 2. Network Traffic Analysis with Wireshark

**Type:** Hands-on lab project
**Tools:** Wireshark, tshark, Tcpdump
**Skills demonstrated:** Packet analysis, protocol analysis, identifying suspicious traffic

## Objective

Analyse a packet capture, understand what normal traffic looks like, and identify traffic that is unusual, suspicious, or indicative of compromise — without jumping to conclusions from a single packet.

## Analysis method

1. **Get oriented**
   - Capture duration, total packets, top talkers, top protocols
   - What should this network normally be doing?
2. **Follow the conversations**
   - TCP streams, DNS queries, HTTP requests
   - Who talks to whom, how often, and how much data moves?
3. **Look for anomalies**
   - DNS to rare or newly registered domains, DNS tunnelling patterns
   - Unusual ports, beaconing at regular intervals, large outbound transfers
   - Cleartext credentials, unusual user agents, malformed packets
4. **Correlate with other evidence**
   - Does an IP or domain also appear in logs or threat intelligence?
   - Does the timing match an alert or a user report?
5. **Write it up**
   - What was seen, what it likely means, what is still uncertain, and what to do next

## Useful commands

```bash
# Top talkers
tshark -r capture.pcap -q -z conv,ip

# DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -nr

# HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri

# Follow one TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

## Wireshark display filters worth knowing

```
dns
http.request
tcp.flags.syn == 1 and tcp.flags.ack == 0
ip.addr == 192.0.2.10
dns.qry.name contains "example"
```

## Sample write-up structure

- **Capture summary:** [duration, size, protocols, top talkers]
- **Normal baseline:** [what expected traffic looks like]
- **Anomalies found:** [each one, with packet evidence]
- **Assessment:** [benign / suspicious / likely malicious, and confidence level]
- **Recommended actions:** [block, monitor, investigate the host, improve detection]

## What I learned

- Baseline first. You cannot spot "unusual" until you know "usual."
- One suspicious packet is a lead, not a verdict. Look for a pattern across time.
- Clear, evidence-linked write-ups are what turn a capture into a finding an employer can trust.
