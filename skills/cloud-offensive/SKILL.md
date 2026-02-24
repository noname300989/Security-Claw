---
name: cloud-offensive
description: |
  Cloud infrastructure offensive testing engine for AWS, Azure, and GCP. Covers IAM privilege
  escalation, S3/blob misconfiguration analysis, container/Kubernetes escape, serverless function
  abuse, metadata endpoint exploitation, and cloud-native persistence techniques. Maps findings
  to OWASP Cloud Top 10, MITRE ATT&CK for Cloud (Enterprise), and CIS Cloud Benchmarks.
  Integrates Scout Suite, Pacu (AWS), ROADtools (Azure), and gcloud CLI.
metadata:
  {
    "openclaw":
      {
        "emoji": "☁️",
        "requires":
          {
            "bins": ["aws", "python3"],
            "optional": ["scoutsuite", "pacu", "roadtools", "trufflehog"],
          },
        "install":
          [
            {
              "id": "pip-scoutsuite",
              "kind": "shell",
              "cmd": "pip3 install scoutsuite",
              "bins": ["scout"],
              "label": "Install Scout Suite (pip)",
            },
            {
              "id": "pip-pacu",
              "kind": "shell",
              "cmd": "pip3 install pacu",
              "bins": ["pacu"],
              "label": "Install Pacu AWS exploitation framework (pip)",
            },
            {
              "id": "brew-trufflehog",
              "kind": "brew",
              "formula": "trufflehog",
              "bins": ["trufflehog"],
              "label": "Install TruffleHog secret scanner (brew)",
            },
          ],
      },
  }
---

# Cloud Offensive Testing Skill

Comprehensive cloud security assessment aligned with MITRE ATT&CK for Cloud and OWASP Cloud Security.

## Capabilities

### 1. AWS IAM Privilege Escalation

Enumerate and exploit IAM misconfigurations to escalate from low-priv to admin.

**Usage:**

> Test AWS account for IAM privilege escalation paths using access key AKIA...

**Techniques:**

- PassRole abuse
- AssumeRole chaining
- Wildcard policy exploitation
- Permission boundary bypass

**Tools:** `pacu`, `aws cli`, custom IAM analysis scripts

**References:** MITRE ATT&CK: TA0004 (Privilege Escalation), T1078.004

---

### 2. S3 / Azure Blob / GCS Bucket Misconfiguration

Find publicly accessible or world-writeable cloud storage resources.

**Usage:**

> Scan for misconfigured S3 buckets related to target-company

**Checks:**

- Public ACLs / bucket policies
- Unsigned URL access
- Directory listing enabled
- Credential files, config files, backups in buckets

**Tools:** `trufflehog`, `aws s3 ls --no-sign-request`, `nuclei`

**References:** OWASP Cloud Top 10 - Cloud Storage Exposure

---

### 3. Metadata Endpoint Exploitation (SSRF → Cloud)

Exploit SSRF to reach cloud instance metadata services (IMDS) for credential theft.

**Usage:**

> Exploit SSRF at https://target.com/fetch?url= to steal cloud metadata credentials

**Targets:**

- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/`
- Azure: `http://169.254.169.254/metadata/identity/oauth2/token`

**References:** MITRE ATT&CK: T1552.005

---

### 4. Container & Kubernetes Escape

Identify container breakout vectors and Kubernetes privilege escalation paths.

**Usage:**

> Assess this Kubernetes cluster for privilege escalation and container escape

**Checks:**

- Privileged container escape
- Host path mount abuse
- ServiceAccount token theft
- RBAC misconfigurations (ClusterRoleBindings → admin)
- etcd exposure
- Kubelet API exposure

**References:** MITRE ATT&CK for Containers: TA0004, T1611

---

### 5. Serverless / Lambda Function Abuse

Test serverless functions for event injection, resource-based policy misconfigs, and data exposure.

**Usage:**

> Enumerate and test Lambda functions in AWS account for security issues

**Tools:** `pacu` (Lambda modules), aws cli, manual review

**References:** OWASP Serverless Top 10

---

### 6. Cloud Secret & Key Leakage Detection

Scan code repositories, storage, and logs for leaked cloud credentials and secrets.

**Usage:**

> Scan the GitHub repositories of target-company for leaked AWS keys and secrets

**Tools:** `trufflehog`, `gitleaks`

**References:** CWE-798: Hard-coded Credentials

---

### 7. Multi-Cloud Attack Chain Simulation

Simulate realistic attack chains across cloud boundaries (e.g., AWS → Azure federation abuse).

**Usage:**

> Simulate a full kill chain from initial SSRF to cloud admin credential theft

**Example Chain:** SSRF → IMDS → IAM Keys → S3 Data Exfil → Lambda Persistence

---

## Quick Commands

| Action      | Command                                                   |
| ----------- | --------------------------------------------------------- |
| IAM Enum    | `aws iam get-account-authorization-details --output json` |
| Bucket Scan | `aws s3 ls s3://BUCKET --no-sign-request`                 |
| ScoutSuite  | `scout aws --report-name report`                          |
| TruffleHog  | `trufflehog github --org TARGET_ORG`                      |
| K8s Enum    | `kubectl auth can-i --list --namespace=kube-system`       |
