# Spellbinder: IPv6 MITM with DNS Spoofing or Relay

Spellbinder is a Python-based adversary-in-the-middle (AiTM) tool that emulates the behavior of APT actors leveraging SLAAC and Router Advertisements (RA) to bypass traditional DHCPv6 protections. It enables penetration testers to perform internal network assessments where clients automatically configure IPv6 without needing a DHCP server — a common misconfiguration in enterprise environments.

This tool supports both **DNS spoofing** (to redirect all requests to the attacker's IPv6) and **DNS relaying** (to upstream resolvers such as `8.8.8.8`), and includes real-time console logging of DNS queries for visibility.

Notes: the NAT64 IP needs to be a valid IP on the IPv4 subnet when set. The IPs also are not removed on script execution, but this generally is only an issue for the NAT64 interface or if you manually change the IPv6 address consistently. These IPs can be removed manually with the "ip" command. Also, the services for tayga and radvd stay enabled post script and need to be manually stopped. This will be resolved in a later update.  

---

## Features

- **SLAAC + RDNSS spoofing** using `radvd`
- **NAT64 support** via `tayga`
- **DNS response hijacking** using `dnsmasq`
- **Toggle between spoof or relay mode**
- **Live DNS query logging** to the console
- **Built-in cleanup and safety logic**
- **Bypasses DHCPv6 protections by leveraging IPv6 autoconfig behavior**

---

## Requirements

Tested on **Kali Linux** (Debian-based). Install dependencies:

```bash
sudo apt install -y dnsmasq radvd tayga iproute2 net-tools
```

```
sudo python3 spellbinder3.py
```

```
Enter the interface to listen on (default eth0): eth0
Enter the global IPv6 address to assign: 2001:db8:1::2
Enter the NAT64 IPv6 address: 2001:db8:1::3
Enter the NAT64 IPv4 address: 192.168.255.1
Select DNS mode: [1] Spoof all to attacker IPv6 (default)  [2] Relay to 8.8.8.8: 1
```
