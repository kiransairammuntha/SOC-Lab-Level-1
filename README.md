<p align="center">
  <img src="https://assets.tryhackme.com/img/logo/tryhackme_logo_full.svg" alt="TryHackMe Logo" width="300">
</p>

<h1 align="center">🛡️ SOC Level 1 - Security Operations Center Training</h1>

<p align="center">
  <img src="https://img.shields.io/badge/TryHackMe-SOC_Level_1-88cc14?style=flat&logo=tryhackme" alt="TryHackMe">
  <img src="https://img.shields.io/badge/Role-SOC_Analyst-blue?style=flat" alt="Role">
  <img src="https://img.shields.io/badge/MITRE-ATT&CK-red?style=flat" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/badge/NIST-IR_Framework-orange?style=flat" alt="NIST">
  <img src="https://img.shields.io/badge/Status-Completed-success.svg" alt="Status">
</p>

<p align="center">
  <i>Hands-on Security Operations Center analyst training covering SIEM operations, threat intelligence, incident response, and malware analysis through real-world SOC simulation labs.</i>
</p>

---

## 🎯 Project Aim

> **"A SOC analyst doesn't just watch alerts — they hunt threats, investigate incidents, and protect organizations."**

In a world where organizations face **thousands of security alerts daily**, skilled SOC analysts are the frontline defenders. This project demonstrates:

🔍 **Real-world SOC experience** through hands-on simulation labs, not just theoretical knowledge

🛡️ **Blue team defensive skills** — thinking like a defender to protect against attackers

📊 **SIEM mastery** — analyzing logs, correlating events, and detecting threats in real-time

🚨 **Incident response expertise** — from alert triage to full incident investigation and escalation

🎯 **Industry framework alignment** — MITRE ATT&CK, Cyber Kill Chain, and NIST IR methodologies

This is **SOC job simulation training** — practical experience equivalent to entry-level on-the-job exposure.

---

## 📑 Table of Contents

- [🔍 Overview](#-overview)
- [✨ Training Phases](#-training-phases)
- [🏗️ SOC Architecture](#️-soc-architecture)
- [🎯 Attacks & Techniques Covered](#-attacks--techniques-covered)
- [🛠️ Tools & Technologies](#️-tools--technologies)
- [🎓 Skills Demonstrated](#-skills-demonstrated)
- [🏆 Project Achievements](#-project-achievements)
- [📊 Key Metrics & Performance](#-key-metrics--performance)
- [🙏 Acknowledgments](#-acknowledgments)
- [🎬 Project Summary](#-project-summary)
- [📞 Contact & Support](#-contact--support)
- [📊 Project Stats](#-project-stats)

---

## 🔍 Overview

The **SOC Level 1 Learning Path** simulates the real working environment of a **Tier-1 SOC Analyst**, focusing on:

| Function | Description |
|----------|-------------|
| 📡 **Monitoring** | Watching security events across the organization |
| 🔍 **Investigation** | Analyzing alerts to determine if threats are real |
| 🎯 **Detection** | Identifying malicious activity in logs and traffic |
| 📋 **Triage** | Prioritizing incidents based on severity and impact |
| ⬆️ **Escalation** | Handing off critical incidents using industry frameworks |

> ### 💡 Why SOC Level 1?
> 
> Unlike theory-only certifications, this path emphasizes **hands-on operational skills**. Recruiters and SOC managers view this as evidence that you:
> - Understand SOC operations
> - Can work with logs and alerts
> - Know IR fundamentals
> - Are ready for Tier-1 SOC roles
> - Require less onboarding than theory-only candidates

---

## ✨ Training Phases

### Phase 1: SOC & Blue Team Foundations

| Topic | What You Learn |
|-------|----------------|
| **SOC Operations** | How a SOC operates 24×7, tier structure (Tier 1, 2, 3) |
| **Analyst Responsibilities** | Tier-1 duties, alert prioritization, escalation criteria |
| **Team Dynamics** | Blue team vs Red team vs Purple team |
| **Core Concepts** | CIA Triad, Defense-in-Depth, Attack Surface |
| **Frameworks** | Kill Chain vs MITRE ATT&CK |

---

### Phase 2: Log Analysis & SIEM Operations

| Skill | Application |
|-------|-------------|
| **Windows Event Logs** | Login attempts, privilege escalation, PowerShell execution |
| **Linux Logs** | Authentication logs, system logs, sudo activity |
| **Web Server Logs** | Apache/Nginx access and error logs |
| **Firewall/IDS Logs** | Network traffic analysis, blocked connections |
| **SIEM Queries** | Writing and refining search queries for threat detection |

**Investigations Performed:**
- ✅ Failed and successful login attempts
- ✅ Privilege escalation events
- ✅ Suspicious PowerShell execution
- ✅ Lateral movement indicators
- ✅ Timeline reconstruction

---

### Phase 3: Threat Intelligence & Malware Analysis

| Category | Tools & Techniques |
|----------|-------------------|
| **Threat Intel Sources** | VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX |
| **IOC Enrichment** | IP reputation, domain analysis, hash lookups (MD5, SHA-256) |
| **Malware Types** | Trojans, Ransomware, Spyware, Keyloggers, Backdoors |
| **Delivery Mechanisms** | Phishing, malicious attachments, drive-by downloads |
| **Analysis Skills** | Static analysis, behavioral indicators, persistence mechanisms |

---

### Phase 4: Incident Response & Digital Forensics

**NIST Incident Response Lifecycle:**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Preparation │───►│Identification│───►│ Containment │
└─────────────┘    └─────────────┘    └─────────────┘
                                             │
┌─────────────┐    ┌─────────────┐    ┌──────▼──────┐
│   Lessons   │◄───│  Recovery   │◄───│ Eradication │
│   Learned   │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
```

**Incident Scenarios Investigated:**
- 🎣 Phishing email investigation
- 💻 Compromised endpoint analysis
- 🔐 Brute-force attack detection
- 🌐 Suspicious network traffic
- 🚫 Unauthorized access detection

---

### Phase 5: SOC Workflows & Professional Practice

| Methodology | Application |
|-------------|-------------|
| **Alert Triage** | Prioritizing alerts by severity and impact |
| **Playbook Response** | Following standardized incident procedures |
| **MITRE ATT&CK** | Mapping threats to tactics, techniques, procedures |
| **Cyber Kill Chain** | Understanding attack progression stages |
| **Pyramid of Pain** | Assessing difficulty of IOC-based detection |

---

## 🏗️ SOC Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SECURITY OPERATIONS CENTER (SOC)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         SIEM PLATFORM                               │   │
│   │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
│   │   │    Log       │  │    Alert     │  │   Threat     │             │   │
│   │   │  Ingestion   │  │   Engine     │  │   Intel      │             │   │
│   │   └──────────────┘  └──────────────┘  └──────────────┘             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                        SOC ANALYST TIERS                            │   │
│   │                                                                     │   │
│   │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
│   │   │   TIER 1     │  │   TIER 2     │  │   TIER 3     │             │   │
│   │   │  Alert       │  │  Deep        │  │  Threat      │             │   │
│   │   │  Triage      │──►  Analysis    │──►  Hunting     │             │   │
│   │   │  & Monitor   │  │  & Response  │  │  & Research  │             │   │
│   │   └──────────────┘  └──────────────┘  └──────────────┘             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
┌───────┴───────┐          ┌───────┴───────┐          ┌───────┴───────┐
│   ENDPOINTS   │          │   NETWORK     │          │   CLOUD       │
│  Windows/Linux│          │  Firewalls    │          │  AWS/Azure    │
│  Event Logs   │          │  IDS/IPS      │          │  Cloud Logs   │
└───────────────┘          └───────────────┘          └───────────────┘
```

---

## 🎯 Attacks & Techniques Covered

### Attack Types Investigated

| Attack | Description | Detection Method |
|--------|-------------|------------------|
| 🎣 **Phishing** | Social engineering via email | Email header analysis, URL reputation |
| 🔐 **Credential Harvesting** | Stealing login credentials | Failed login patterns, impossible travel |
| 🔓 **Brute Force** | Password guessing attacks | Authentication log analysis |
| 🦠 **Malware Execution** | Running malicious code | Process monitoring, hash analysis |
| 📡 **Command & Control** | Attacker communication channel | Network traffic analysis |
| 🔄 **Lateral Movement** | Moving across network | Login correlation, access patterns |
| ⬆️ **Privilege Escalation** | Gaining higher access | Sudo logs, admin activity |
| 🏠 **Persistence** | Maintaining access | Registry, scheduled tasks, startup items |

### MITRE ATT&CK Coverage

| Tactic | Techniques Studied |
|--------|-------------------|
| **Initial Access** | Phishing, valid accounts |
| **Execution** | PowerShell, command-line |
| **Persistence** | Registry run keys, scheduled tasks |
| **Privilege Escalation** | Sudo exploitation, token manipulation |
| **Defense Evasion** | Log clearing, obfuscation |
| **Credential Access** | Brute force, credential dumping |
| **Discovery** | Network scanning, system enumeration |
| **Command & Control** | C2 channels, beaconing |

---

## 🛠️ Tools & Technologies

### Security Platforms

| Tool Category | Technologies |
|---------------|--------------|
| **SIEM** | Splunk-style, Elastic-style platforms |
| **Threat Intel** | VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX |
| **Log Analysis** | Windows Event Viewer, Linux syslog |
| **Malware Analysis** | Sandbox environments, static analysis tools |

### Operating Systems

| OS | Log Sources Analyzed |
|----|---------------------|
| **Windows** | Event logs, Registry, PowerShell, Processes |
| **Linux** | Auth logs, System logs, Audit logs |

### Frameworks Applied

| Framework | Application |
|-----------|-------------|
| **MITRE ATT&CK** | Threat mapping and detection |
| **Cyber Kill Chain** | Attack stage identification |
| **NIST IR** | Incident response procedures |
| **Pyramid of Pain** | IOC effectiveness assessment |

---

## 🎓 Skills Demonstrated

### Technical Skills
- 📊 **SIEM Operations** — Log ingestion, query writing, alert management
- 🔍 **Log Analysis** — Windows, Linux, web server, firewall logs
- 🎯 **Threat Detection** — IOC-based and behavior-based detection
- 🦠 **Malware Analysis** — Static analysis, behavioral indicators
- 🔄 **Incident Response** — NIST lifecycle, documentation, escalation
- 🌐 **Threat Intelligence** — IOC enrichment, reputation analysis

### Security Knowledge
- 🛡️ **SOC Operations** — Tier structure, workflows, playbooks
- 📋 **MITRE ATT&CK** — Tactics, techniques, procedures mapping
- 🔗 **Cyber Kill Chain** — Attack progression understanding
- 🔐 **Attack Techniques** — Phishing, brute force, lateral movement
- 📈 **Risk Assessment** — Severity classification, prioritization

### Professional Competencies
- 📝 **Analyst Documentation** — Incident reports, escalation notes
- 🗣️ **Communication** — Clear risk articulation to stakeholders
- ⏱️ **Time Management** — Working under pressure, alert prioritization
- 🔄 **Process Adherence** — Following SOC playbooks and procedures
- 🤝 **Team Collaboration** — Analyst-to-IR handoff preparation

---

## 🏆 Project Achievements

### What This Project Demonstrates
- ✅ Completed comprehensive SOC analyst training program
- ✅ Hands-on experience with real-world SOC simulation labs
- ✅ Proficiency in SIEM log analysis and threat detection
- ✅ Incident response capabilities using NIST framework
- ✅ Threat intelligence enrichment and IOC analysis
- ✅ Malware analysis fundamentals and artifact recognition
- ✅ MITRE ATT&CK framework application for threat mapping

### Business Value
- 💰 **Job-Ready Skills** — Practical experience equivalent to entry-level SOC exposure
- 📉 **Reduced Onboarding** — Less training required than theory-only candidates
- 🎯 **Immediate Contribution** — Can handle Tier-1 SOC responsibilities from day one
- 📈 **Career Foundation** — Solid base for SOC Analyst career progression
- ✅ **Industry Recognition** — TryHackMe certification valued by employers

---

## 📊 Key Metrics & Performance

### Training Coverage

| Metric | Value |
|--------|-------|
| **Training Phases** | 5 comprehensive phases |
| **Attack Types** | 8+ attack categories |
| **MITRE Tactics** | 8 tactics covered |
| **Log Sources** | Windows, Linux, Web, Network |
| **Frameworks** | MITRE ATT&CK, Kill Chain, NIST IR |
| **Tools Used** | SIEM, Threat Intel, Malware Sandbox |

### SOC Analyst Readiness

| Capability | Proficiency |
|------------|-------------|
| 📡 Alert Monitoring | ✅ Job-Ready |
| 🔍 Log Analysis | ✅ Job-Ready |
| 🎯 Threat Detection | ✅ Job-Ready |
| 📋 Incident Triage | ✅ Job-Ready |
| ⬆️ Escalation | ✅ Job-Ready |
| 📝 Documentation | ✅ Job-Ready |

---

## 🙏 Acknowledgments

**Training Platform:**
- [TryHackMe](https://tryhackme.com/) — Hands-on cybersecurity training

**Frameworks & Standards:**
- [MITRE ATT&CK](https://attack.mitre.org/) — Threat knowledge base
- [NIST](https://www.nist.gov/) — Incident response framework
- [Lockheed Martin](https://www.lockheedmartin.com/) — Cyber Kill Chain

**Threat Intelligence Sources:**
- VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX

**Security Community:**
- Blue team defenders worldwide
- SOC analyst best practices
- Open-source security tools

---

## 🎬 Project Summary

This SOC Level 1 training represents **comprehensive Security Operations Center analyst preparation** that combines:

✅ **Hands-on labs** (Real-world SOC simulation)
✅ **SIEM operations** (Log analysis and threat detection)
✅ **Threat intelligence** (IOC enrichment and analysis)
✅ **Incident response** (NIST framework implementation)
✅ **Malware analysis** (Static analysis and behavioral indicators)
✅ **Industry frameworks** (MITRE ATT&CK, Cyber Kill Chain)

**Demonstrates:**
- SOC Tier-1 analyst capabilities
- Log analysis and SIEM proficiency
- Threat detection and investigation skills
- Incident response procedures
- Professional documentation abilities

**Delivers:**
- Job-ready SOC skills
- Practical blue team experience
- Industry-recognized certification
- Interview-ready knowledge
- Career foundation for security roles

**Perfect For:**
- SOC Analyst (Tier 1) roles
- Junior Security Analyst positions
- Cyber Defense Analyst opportunities
- Security Operations careers
- Blue Team positions

---

## 📞 Contact & Support

- **Project Repository**: https://github.com/kiransairammuntha/SOC-Lab-Level-1
- **Issues**: https://github.com/kiransairammuntha/SOC-Lab-Level-1/issues
- **Discussions**: https://github.com/kiransairammuntha/SOC-Lab-Level-1/discussions

---

## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/kiransairammuntha/SOC-Lab-Level-1?style=social)
![GitHub forks](https://img.shields.io/github/forks/kiransairammuntha/SOC-Lab-Level-1?style=social)
![GitHub issues](https://img.shields.io/github/issues/kiransairammuntha/SOC-Lab-Level-1)
![GitHub pull requests](https://img.shields.io/github/issues-pr/kiransairammuntha/SOC-Lab-Level-1)

---

<div align="center">

**Built with ❤️ for Blue Team Defenders**

**Monitor. Detect. Investigate. Respond.**

**Hands-On Training • Industry Frameworks • Job-Ready Skills**

[⬆ Back to Top](#️-soc-level-1---security-operations-center-training)

</div>
