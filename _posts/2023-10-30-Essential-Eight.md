---
layout: post
title: Essential Eight Explainers
date: 2023-10-30 10:14:00-0400
description: Essential Eight security controls.
tags: ACSC PSPF ASD ACSC
categories: Essential-Eight
thumbnail: /assets/img/2023-essentialeight.png
giscus_comments: false
related_posts: false
toc:
  beginning: true
featured: false
---

## What are the Essential Eight

The Australian Signals Directorate's <a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-explained"> Essential Eight Strategies to Mitigate Cyber Security Incidents</a> was developed as a prioritised baseline to assist organisations in protecting their systems against a range of cyber threats.

Notably, the Essential Eight is just a starting point and is not exhaustive. Organisations should conduct regular risk assessments and adopt additional strategies based on their specific threat environment.

For government entities covered by the Protective Security Policy Framework (PSPF), <a href="https://www.protectivesecurity.gov.au/publications-library/policy-10-safeguarding-data-cyber-threats">Policy 10: Safeguarding data from cyber threats</a> specifies that in addition to implementing the Essential Eight, entities should:

>_"[consider] which of the remaining mitigation strategies from the <a href="https://www.cyber.gov.au/acsc/view-all-content/strategies-to-mitigate-cyber-security-incidents">Strategies to Mitigate Cyber Security Incidents</a> need to be implemented to achieve an acceptable level of residual risk for their entity."_

Over the coming months, I'll endeavour to produce PoCs and more detailed explainers that demonstrate why each of the Essential Eight is important and add to the <a href="https://emdeh.com/essential-eight-explainers/">Essential Eight Collection</a>, currently available in the navbar.

The table below lists the Essential Eight, the typical exploits each strategy helps protect against and a brief example.

## Essential Eight Strategies
1 - Application Control
2 - Patch Applications
3 - Configure Microsoft Office macro settings
4 - User Application Hardening
5 - Restrict Administrative Privileges
6 - Patch Operating Systems
7 - Multi-Factor Authentication
8 - Daily Backups

| Strategy | Typical Exploits Protected Against | Example Exploit |
|----------|-------------------------------------|-----------------|
| Application Control | Unauthorised/malicious software execution. | A user unknowingly downloads and runs ransomware. |
| Patch Applications | Exploitation of known software vulnerabilities. | Attacker exploits a known vulnerability in a PDF reader to run malicious code. |
| Configure Microsoft Office macro settings | Macro-based malware. | A user opens an Office document from a phishing email which runs a malicious macro. |
| User Application Hardening | Drive-by downloads and web-based malicious content. | A user visits a compromised website which then attempts to run Flash-based malware. |
| Restrict Administrative Privileges | Attacks that require admin rights to execute. | An attacker gains user credentials that have unnecessary privileges and install keyloggers. |
| Patch Operating Systems | Exploitation of known OS vulnerabilities. | Attacker exploits a known Windows vulnerability to gain remote code execution. |
| Multi-Factor Authentication | Credential theft or brute-force attacks. | An attacker has a user's password and can access their account remotely without the need for additonal authentication factors. |
| Daily Backups | Data loss due to ransomware, hardware failures, or accidental deletions. | Ransomware encrypts a user's files, but they can't be restored from a backup. |