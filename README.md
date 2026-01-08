Got it 👍

You want \*\*the exact content you pasted\*\*, but \*\*reformatted to match the short, clean GitHub style shown in SS1\*\* (compact headings + bullets), \*\*not rewritten\*\*, \*\*not inflated\*\*.



Below is your \*\*README.md in SS1 format\*\*, derived strictly from what you pasted.



You can \*\*copy-paste this directly\*\*.



---



```markdown

\# VPN over SLiRP – User-Space Virtual Private Network



A lightweight \*\*user-space Layer-3 VPN\*\* implemented using \*\*Linux TUN interfaces\*\* and \*\*SLiRP-based networking\*\*, enabling encrypted IP tunneling over UDP without kernel VPN modules or IPsec stacks.



\## Overview

\- Implements raw IP packet capture, encryption, and forwarding entirely in user space

\- Uses UDP-based tunneling with symmetric encryption

\- Supports bidirectional traffic, NAT handling, and DNS routing via SLiRP

\- Validated across AWS regions under real-world latency and NAT conditions



\## Architecture

\- \*\*Client:\*\* Captures IP packets from a TUN interface, encrypts and encapsulates them over UDP, and injects return traffic back into TUN

\- \*\*Server:\*\* Decrypts packets, performs user-space NAT/forwarding using SLiRP, and returns response traffic over UDP



\## Data Flow

```



Application

↓

TUN Interface

↓

Client → Encrypt + UDP

↓

Server → Decrypt

↓

SLiRP (User-Space NAT)

↓

Internet

↓

SLiRP → Encrypt + UDP

↓

Client → TUN → Application



```



\## Key Design Decisions

\- User-space only (no kernel VPN modules, no IPsec/WireGuard)

\- SLiRP for NAT, DNS, and outbound connectivity (10.0.2.0/24 model)

\- UDP transport for tunneling and NAT traversal

\- IV-based symmetric encryption with explicit packet framing



\## Features

\- Layer-3 IP tunneling via TUN

\- Encrypted UDP encapsulation

\- User-space NAT and forwarding

\- DNS support through SLiRP virtual gateway

\- Bidirectional traffic handling with kill-switch routing

\- Cross-region deployment and validation



\## Deployment

\- \*\*Server:\*\* AWS EC2 (Canada), public UDP endpoint with SLiRP forwarding

\- \*\*Client:\*\* AWS EC2 (India), TUN-based packet capture and injection



Validated under real-world latency, firewall, and NAT traversal constraints.



\## Validation

\- tcpdump on TUN interface and UDP socket

\- ping and traceroute through the tunnel

\- DNS resolution and HTTPS traffic verification

\- Cross-region latency testing

\- Failure scenarios (client restarts, UDP session resets)



\## Security Notes

\- Encryption applied only to tunneled IP payloads

\- Static key management (demo-focused)

\- No forward secrecy or authentication layer

\- Not intended as a production-grade VPN



\## Limitations

\- UDP packet loss impacts throughput

\- No congestion control beyond UDP behavior

\- Static encryption keys

\- Single-client focused design

\- SLiRP performance lower than kernel-space NAT



\## Technologies

C, Linux Networking, TUN/TAP, SLiRP, UDP, AES, iproute2, iptables, tcpdump, AWS EC2



\## Learning Outcomes

\- User-space packet handling and tunneling

\- NAT behavior using SLiRP

\- Linux routing and traffic isolation

\- VPN failure modes and limitations

\- Cross-region network validation



\## Disclaimer

For educational and experimental use only. Not suitable for production VPN deployment.

```





