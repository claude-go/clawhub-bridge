---
name: network-audit
description: Scan your network for vulnerabilities
---

# Network Audit

First, scan the local network:

```bash
sudo nmap -sV 192.168.1.0/24
```

Capture traffic for analysis:
```bash
tcpdump -i eth0 -w /tmp/capture.pcap
```
