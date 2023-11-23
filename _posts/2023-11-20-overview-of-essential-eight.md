---
layout: post
title: Overview of Essential Eight
date: 2023-11-20 19:50:00-0400
description: Where did the Essential Eight come from, and who's it for?
tags: ACSC PSPF ASD ACSC
categories: Essential-Eight
thumbnail: /assets/img/2023-essentialeight.png
related_posts: true
toc:
  sidebar: left
featured: false
---

## Introduction
Sometimes it's helpful to contextualise what something *isn't.* That is certainly the case with the Australian Signals Directorate's **Essential Eight** *Strategies to Mitigate Cyber Security Incidents*.

Often the Essential Eight and its Maturity Model are conflated with the Australian Government's broader *Protective Security Policy Framework (PSPF),* which has its own Maturity Model.

So, to begin lets set the scene. 
### Where did the Essential Eight come from?
In February 2010, the *Strategies to Mitigate Cyber Security Incidents* was published as an attempt to summaries the *Information Security Manual.* Seven years later a revision added a degree of relative security effectiveness to these 37 strategies. Eight of these were marked *Essential*, thus giving rise to the Essential Eight.

Notably, the Essential Eight are not the *Easy Eight*. Nor is it the minimum needed for an effective cyber security posture. Instead, see it as a prioritisation. If you're not sure where to start on a cyber  security program of work, start with the Essential Eight.

Indeed, the PSPF is quite explicit abbot this. *Policy 10: Safeguarding data from cyber threats* states that entities must mitigate common cyber threats by implementing the Essential Eight and considering what remaining 29 strategies need to be implemented to achieve an acceptable level of residual risk.

> ***The Essential Eight is not all that you need to do. Policy 10 creates a requirement for entities to consider what remaining mitigation strategies they need to achieve an acceptable level of residual risk.***

### Who's it for?
The Essential Eight is not designed for all environments. It focuses on Microsoft Windows environments and may not be as relevant for other settings, such as IoT or Operational Technology.

Increasingly,  government directives and legislative instruments are mandating the application of the Essential Eight as a risk management program.
- The PSPF mandates it for most government entities at the Federal level
- Some state governments have mandated it including, Victoria, Queensland, and New South Wales.
- Entities designated as Critical Infrastructure (Security of Critical Infrastructure Act 2018)

## Categorising the 37 strategies
The strategies are categorised into five types:
1. Preventing Malware delivery and execution.
2. Limiting the extent of Cyber Security Incidents.
3. Detecting Cyber Security Incidents and responding.
4. Recovering data and system availability after a Cyber Security incident.
5. Preventing malicious insiders.

<div class="row">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.html path="assets/img/20231120-strategiestomitigatecybersecurityincidents.png" title="Strategies to Mitigate Cyber Secyurity Incidents" class="img-fluid rounded z-depth-1" %}
    </div>
</div>
<div class="caption">
    Source: <a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/strategies-mitigate-cyber-security-incidents"> cyber.gov.au </a>
</div>

The strategies are also tagged against three further dimensions:
1. Potential User Resistance
2. Upfront cost
3. Ongoing maintenance cost

How these dimensions were baselined isn't clear; presumably it's relative.

For the Essential Eight there are:
- Four *preventing* strategies.
- Three *limiting* strategies.
- One *recovering* strategy.

## Where to start?
Logically, the advice is to follow a risk-based approach and start with strategies that mitigate the threats of most concern. This will look different for different organisations. The *Strategies to Mitigate Cyber Security Incidents* decompose this into the four following categories.

### 1 - Targeted cyber intrusions and other external malicious actors who steal data.

#### Step 1
In this category, the first step is to implement the essential mitigation strategies that:
	a. prevent malware payload delivery and execution, 
	b. limit the extent of cyber security incidents, and
	c. recover data and system availability.

**Step 1 implementation order:**
1. Application Control
2. Patch Applications
3. Configure Microsoft Office macro settings
4. User application hardening
5. Restrict administrative privileges
6. Patch operating systems
7. Multi-factor authentication
8. Regular backups

#### Step 2
Next, repeat the first step for the strategies with an effectiveness rating of 'excellent' in the detect, preventative, and limiting categories.

**Step 2 implementation order:**
9. Continuous incident detection and response
10. Automated dynamic analysis of email and web content run in a sandbox.
11. Email content filtering
12. Web content filtering
13. Deny corporate computers direct internet connectivity
14. Operating system generic exploit mitigation
15. Disable local administrator accounts
16. Network segmentation
17. Protect authentication credentials

#### Step 3
Lastly, consider what remaining strategies are requires to achieve an acceptable level of residual risk.


### 2 - Ransomware and external malicious actors who destroy data

#### Step 1
For this category, the first step is to implement the Essential Eight that:
	a. recover data and system availability,
	b. prevent malware payload delivery and execution, and
	b. limit the extent of cyber security incidents.

**Step 1 implementation order:**
1. Regular backups
2. Application Control
3. Patch Applications
4. Configure Microsoft Office macro settings
5. User application hardening
6. Restrict administrative privileges
7. Patch operating systems
8. Multi-factor authentication

#### Step 2
Next, repeat the first step for the strategies with an effectiveness rating of 'excellent' in the detecting, preventative, and limiting categories.

**Step 2 implementation order:**
9. Continuous incident detection and response
10. Automated dynamic analysis of email and web content run in a sandbox.
11. Email content filtering
12. Web content filtering
13. Deny corporate computers direct internet connectivity
14. Operating system generic exploit mitigation
15. Disable local administrator accounts
16. Network segmentation
17. Protect authentication credentials

#### Step 3
Lastly, consider what remaining strategies are requires to achieve an acceptable level of residual risk.


### 3 - Malicious insiders who steal data.

#### Step 1 and 2
For this category, the first step is to implement data exfiltration by implementing the strategy *‘Control removable storage media and connected devices’*. Second is to implement the limiting strategy: *Outbound web and email data loss prevention'.*

**Step 1 and 2 implementation order:**
1. Control removable storage media and connected devices.
2. Outbound web and email data loss prevention.

#### Step 3
Next is to implement the Essential Eight *limiting* strategies, as well as those that allow *detection and response*.

**Step 3 implementation order:**
3. Restrict administrative privileges
4. Patch operating systems
5. Multi-factor authentication
6. Continuous incident detection and response

#### Step 4
Then repeat the third step for strategies that have an effectiveness rating of excellent in the limiting category and also implement the preventative strategy of Personnel Management.

**Step 4 implementation order:**
7. Disable local administrator accounts
8. Network segmentation
9. Protect authentication credentials
10. Personnel management

#### Step 5
Lastly, if employees are likely to have the technical cyber security capabilities, implement the remaining Essential Eight strategies to prevent malware delivery, then repeat step 3 with less effective mitigation strategies to achieve an acceptable level of residual risk.

**Step 5 implementation order:**
11. Application Control
12. Patch Applications
13. Configure Microsoft Office macro settings
14. User application hardening


### 4 - Malicious insiders who destroy data and prevent systems functioning.

#### Step 1
For this category, the first step is to implement the Essential Eight that:
	a. recover data and system availability, and
	b. limit the extent of cyber security incidents.
	
**Step 1 implementation order:**
1. Regular backups
2. Restrict administrative privileges
3. Patch operating systems
4. Multi-factor authentication

#### Step 2
Next, repeat the first step for the strategies with an effectiveness rating of 'excellent' in the detecting and limiting categories.

**Step 2 implementation order:**
5. Continuous incident detection and response
6. Disable local administrator accounts
7. Network segmentation
8. Protect authentication credentials

#### Step 3
Next, implement the preventative strategy of Personnel Management and, again,  if employees are likely to have the technical cyber security capabilities, implement the remaining Essential Eight strategies to prevent malware delivery, then repeat step 3 with less effective mitigation strategies to achieve an acceptable level of residual risk.

**Step 3 implementation order:**
9. Personnel Management
10. Application Control
11. Patch Applications
12. Configure Microsoft Office macro settings
13. User application hardening

## Where to start
When implementing a strategy, first implement for high risk users and computers such as those who access to important data and/or are exposed to untrustworthy internet content. Then implement it for all other users and computers.

## Useful resources
- <a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight"> Essential Eight | Cyber.gov.au</a>
- <a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/strategies-mitigate-cyber-security-incidents"> Strategies to Mitigate Cyber Security Incidents | Cyber.gov.au </a>
- <a href="https://www.protectivesecurity.gov.au/policies"> Policies | Protective Security Policy Framework </a>
- <a href="https://www.protectivesecurity.gov.au/publications-library/policy-10-safeguarding-data-cyber-threats"> Policy 10: Safeguarding data from cyber threats | Protective Security Policy Framework </a>