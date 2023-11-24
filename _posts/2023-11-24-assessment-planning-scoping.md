---
layout: post
title: Assessment planning and scoping
date: 2023-11-24 07:00:00-0400
description: The four stages of assessment
tags: ACSC PSPF ASD ACSC
categories: Essential-Eight
thumbnail: /assets/img/2023-essentialeight.png
related_posts: true
toc:
  sidebar: left
featured: false
---

## Introduction
The planning and scoping stages of an assessment are essential for structuring the process and ensuring that the security insights gained accurately represent the environment being assessed. It's vital to take into account the context in which an organisation operates, including the threat landscape during this stage. In this context, the threat landscape can mean the primary threat the organisation is facing. For example, insider threats or external threats - including the level of threat sophistication.

Assessors should examine the organisation's policies and procedures, conduct comprehensive tests of technical controls pertinent to each strategy, and assess their effectiveness. Determining the desired maturity level of the organization under assessment is key to guiding the assessment and establishing the appropriate scope and methods.

The type and quality of evidence collected will play a role in the assessment outcomes, so it's critical to ensure that the evidence gathered is of high quality and reliable as this will underpin the report's conclusions and recommendations.

When there are mandatory requirements for the implementation of the Essential Eight, there is a need for assessment to attest the level of maturity of the organisation's cyber security controls. The assessment process, however, is intended to provide an organisation with actionable insights. For this reason, organisations who do not have a mandated requirement, will still find regular assessment helpful as a way to identify improvements.

>***Non-corporate entities within the Australian Government are typically required to obtain a Maturity Level Two within the broader context of the mandatory Protective Security Policy Framework (PSPF).***

The following sections describe the four assessment stages.

## Stage 1 - Assessment planning and preparation
During this stage pre-planning is undertaken to build a contextual overview of the organisation and the threat landscape it operates in. The assessor will aim to gain an understanding of the infrastructure, the teams the assessor will need to interact with, and the skills required to complete the assessment.

As part of planning, the assessor should discuss the following with the asset owner:
- Determine asset classification and assessment scope.
- Requirements around access to low and high-privileged user accounts, devices, documentation, personnel, and facilities.
- Any approvals required to run scripts and tools within the environment.
- Evidence collection and protection requirements, including following the conclusion of the assessment.
- Finalising approval to use tools and scripts on sample systems/servers/networks.
- Requirements for where the assessment report will be developed (e.g. on the organisation's system or externally).
- How stakeholder engagement and consultation should be approached, including confirming key points of contact.
- Whether any managed service providers support or manage any aspects of the system(s) under assessment; including appropriate points of contact if so.
- Obtaining copies of any previously completed assessment reports for the system.
- Agreement on appropriate use, retention and marketing of the assessment report by both parties.

At the end of this stage, the assessor should have developed the assessment test plan.
## Stage 2 - Assessment scoping
Different maturity levels will impact aspects or components of the assessment. During this stage the assessor should become familiar with the requirements for the target maturity level, so the assessment approach and test plan can be adjusted accordingly.

> ***The Essential Eight should be implemented and assessed as a package. If a system has not previously been assessed and demonstrated to meet Maturity Level One, that system should not be assessed for Maturity Level Two. Likewise, a system should be assessed and demonstrated to meet Maturity Level Two before being assessed for Maturity Level Three.***

As part of determining the appropriate assessment approach, the assessor should conduct the following activities:
- Make use of asset registers that describe the environment to determine the applicability of the Essential Eight.
- Conduct workshops with the system owners to identify and agree on the precise assessment scope, including out-of-scope items.
- Agree with system owners on the assessment duration and milestones.
- Obtain an approximate breakdown of the operating systems used within the environment.
- Determine the necessary sample size to accurately represent all in-scope assets and types of assets.
- Document any assessment limitations, including sample sizes and constraints in the assessment report.

### Evidence quality
Assessments should strive to gather and use the highest calibre of evidence to effectively support the conclusions on the effectiveness of controls. Evidence quality requirements should be considered and discussed at this stage.

It's important to use a mix of both qualitative and quantitively techniques, as these will often complement each other and allow for cross-referencing. Qualitative techniques may included reviewing documentation and interviewing system administrators. Quantitative techniques could include reviewing system configurations or utilising tools and scripts.

When conducting assessments, the quality of evidence can typically be categorised as follows:

| Quality | Description |
|---|---|
| Excellent evidence | Testing a control with a simulated activity that is designed to validate it is implemented *and* effective (e.g. attempting to run an application to check application control rulesets).  |
| Good evidence |Review configuration settings of a system *through the system's interface* (not screenshots or as-built documentation) to determine whether it a control should theoretically be enforced. |
| Fair evidence |Review a copy of a system's configuration (e.g. using reports or screenshots) to determine whether it should enforce an expected control. |
|Poor evidence |A policy or verbal statement of intent (e.g. sighting mention of controls within artefacts such as as-built documents). |

<br>
## Stage 3 - Assessment of controls
At this stage the effectiveness of the controls within the Essential Eight are tested against the target Maturity Level.

ACSC ahs developed standardised assessment outcomes which must be used.

Each control can be assessed as:
- **Effective**: The organisation is effectively meeting the control's objective.
- **Ineffective**: The organisation is not adequately meeting the control's objective.
- **Alternate control:** The organisation is effectively meeting the control's objective through an alternate control.
- **Not assessed:** The control has not yet been assessed.
- **Not applicable:** The control does not apply to the system or environment.
- **No visibility:** The assessor was unable to obtain adequate visibility of a control's implementation. 

Importantly, the Essential Eight Maturity Model does not allow for risk acceptance without compensating controls. If a system owner has accepted a  risk with no compensating controls, the mitigation strategy must be considered not implemented.

Moreover, when evaluating the efficacy of compensating controls, it's important to verify that the level of protection the compensating control(s) offer is commensurate to that prescribed by the Essential Eight to protect against the level of adversarial tradecraft for the target Maturity Level.

>***There is no scope in the Essential Eight model that allows for risks to be accepted without commensurate compensating controls.***

## Stage 4 - Development of the assessment report
In the final stage, the assessor will develop the security assessment report.

### Understanding maturity levels.
The report will contextualise the assessment against the Maturity Model. The Maturity Model contains four levels that provide a way for an organisation to measure its progress in implementing the Essential Eight while also identifying areas for improvement.

There are three target levels, based on increasingly sophisticated levels of adversarial tradecraft. Level 0 exists for designating instances where the requirements of the first maturity level are not met.

At **Maturity Level 0** weaknesses exist in the overall cyber security posture. This is also the default starting position if no assessment has been done previously.

At **Maturity Level One** the focus is on protection against malicious actors who are content to simply leverage widely available tradecraft. This level maturity does not offer protection against APT tradecraft or other persistent threats, including insider threats.

At **Maturity Level Two** a level of protection is reached that is sufficient to mitigate threats from malicious actors who are willing to invest more time in a target and in the effectiveness of their tools.

At **Maturity Level Three** the focus is on threats who are more adaptive and much less reliant on public tools and techniques, such as state-sponsored actors, military operations, other APTs.

### Report validity
There's no expiry date on the assessment report. Theoretically an assessment could be indefinite but assessors should be cautious of relying on previous report that are aged,  and should  consider doing a gap analysis to determine any deviations from succeeding changes to the Essential Eight, as well as changes within the environment itself.

### Treatment and exceptions
The use of exceptions for a system need to be documented and approved by an appropriate authority through a formal process. For government entities, the appropriate authority may be defined in the broader PSPF.

Documentation for exceptions should include the scope and justification for the exception, as well as the following detail of the compensating controls:
- Reason, scope, and justification for compensating controls.
- Anticipated implementation lifetime of the compensating control(s).
- The review schedule of the compensating control.
- The system risk rating before and after the compensating control was implemented.
- Any caveats around the use of the system because of the exception.
- The formal acceptance from the appropriate authority of any residual risk for the system.
- When the need for the exception will next be considered by the appropriate authority, noting exceptions should not be approved beyond one year.

## Useful resources
- <a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-assessment-process-guide">Essential Eight Assessment Process Guide | Cyber.gov.au</a>
- <a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model">Essential Eight Maturity Model | Cyber.gov.au</a>
- <a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model-faq">Essential Eight Maturity Model FAQ | Cyber.gov.au</a>
