---
layout: post
title: Essential Eight Scenarios
date: 2023-10-30 10:14:00-0400
description: Essential Eight security controls
tags: ACSC PSPF
categories: Essential-Eight
giscus_comments: false
related_posts: false
toc:
  beginning: true
---

## What are the Essential Eight

The Australian Cyber Security Centre (ACSC) developed the "Essential Eight" as a baseline of eight mitigation strategies to assist organisations in protecting their systems against a range of cyber threats. The Essential Eight strategies are designed to be implemented as a package.

Importantly, the Essential Eight is just a starting point and is not exhaustive. Organisations should conduct regular risk assessments and adopt additional strategies as needed based on their specific threat environment.

Over the coming months, I'll endeavour to produce PoCs that demonstrate why each one is important, and add it the 

The table below lists the Essential Eight, along with the type of typical exploits each strategy helps protect against and a brief example.

## Essential Eight Strategies
1 - Application Whitelisting
2 - Patch Applications
3 - Disable Untrusted Microsoft Office Macros
4 - User Application Hardening
5 - Restrict Administrative Privileges
6 - Patch Operating Systems
7 - Multi-Factor Authentication
8 - Daily Backups

| Strategy | Typical Exploits Protected Against | Example Exploit |
|----------|-------------------------------------|-----------------|
| Application Whitelisting | Unauthorised/malicious software execution | A user unknowingly downloads and runs ransomware. |
| Patch Applications | Exploitation of known software vulnerabilities | Attacker exploits a known vulnerability in a PDF reader to run malicious code. |
| Disable Untrusted Microsoft Office Macros | Macro-based malware | A user opens an Office document from a phishing email which runs a malicious macro. |
| User Application Hardening | Drive-by downloads and web-based malicious content | A user visits a compromised website which then attempts to run Flash-based malware. |
| Restrict Administrative Privileges | Attacks that require admin rights to execute | An attacker gains user credentials but cannot install keyloggers due to lack of admin privileges. |
| Patch Operating Systems | Exploitation of known OS vulnerabilities | Attacker exploits a known Windows vulnerability to gain system access. |
| Multi-Factor Authentication | Credential theft or brute-force attacks | An attacker has a user's password but cannot access their account without the second authentication factor. |
| Daily Backups | Data loss due to ransomware, hardware failures, or accidental deletions | Ransomware encrypts a user's files, but they can be restored from a backup. |

Done and dusted.