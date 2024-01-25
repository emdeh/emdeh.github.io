---
layout: post
title: Application Control
date: 2024-01-25 13:00:00-0400
description: Assessing Application Control
tags: ACSC PSPF ASD ACSC application-control
categories: Essential-Eight
thumbnail: /assets/img/2023-essentialeight.png
related_posts: true
toc:
  sidebar: left
featured: false
---

# Introduction
<br>
<br>

## Control objective

The objective of the **Application Control** strategy is to ensure applications are only accessible from appropriate locations and to the appropriate users.
## Expectation

It is expected that organisations have a comprehensive approach to managing and controlling the execution of software applications.

The approach needs to include the full lifecycle of approving, deploying, and removing software applications. At higher maturity levels, log retention and monitoring are required.

The scope of application control is also extended from just workstations to internet-facing servers at maturity level 2 and all workstations servers at maturity level 3.
## Implementing application control

- Identify business critical applications and formally approve their use.
- Develop application control rules to ensure only approved applications are allowed to execute.
- Maintain the application control rules using a change management program.
- Validate application control rules on an annual or more frequent basis.
# Assessment scope

When carrying out application control assessments, it's important to consider paths related to standard user profiles and temporary directories that are utilised by operating systems, web browsers, and email clients. These can include:

- `%userprofile%*`
- `%temp%*`
- `%tmp%*`
- `%windir%\Temp*`

Based on the system's setup, some overlap may be present; for example, `%temp%` and `%tmp%` are usually found within `%userprofile%`.

>*It is important to note that the last major update to the maturity model introduced compiled Hypertext Markup Language (HTML) (`.chm` files), HTML applications (`.hta` files) and control panel applets (`.cpl` files) to the list of file types that need to be controlled. Some application control solutions may not support these file types.*

# Maturity Level requirements

<table>
    <tr>
        <th>Level 1</th>
        <th>Level 2</th>
        <th>Level 3</th>
    </tr>
    <tr>
        <td>-</td>
        <td><strong>Application control is implemented on workstations and internet-facing servers.</strong></td>
        <td>Application control is implemented on workstations and <strong>servers</strong>.</td>
    </tr>
    <tr>
        <td>The execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets is prevented on workstations from within standard user profiles and temporary folders used by the operating system, web browsers and email clients.</td>
        <td><strong>Application control restricts</strong> the execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets <strong>to an organisation-approved set</strong>.</td>
        <td>Application control restricts the execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications, control panel applets <strong>and drivers</strong> to an organisation-approved set.</td>
    </tr>
    <tr>
        <td>-</td>
        <td>-</td>
        <td><strong>Microsoft’s ‘recommended block rules’ are implemented.</strong></td>
    </tr>
    <tr>
        <td>-</td>
        <td>-</td>
        <td><strong>Microsoft’s ‘recommended driver block rules’ are implemented.</strong></td>
    </tr>
    <tr>
        <td>-</td>
        <td>-</td>
        <td><strong>Application control rulesets are validated on an annual or more frequent basis.</strong></td>
    </tr>
    <tr>
        <td>-</td>
        <td><strong>Allowed and blocked execution events on workstations and internet-facing servers are logged.</strong></td>
        <td>Allowed and blocked execution events on workstations and <strong>servers</strong> are <strong>centrally</strong> logged.</td>
    </tr>
    <tr>
        <td>-</td>
        <td>-</td>
        <td><strong>Event logs are protected from unauthorised modification and deletion.</strong></td>
    </tr>
    <tr>
        <td>-</td>
        <td>-</td>
        <td><strong>Event logs are monitored for signs of compromise and actioned when any signs of compromise are detected.</strong></td>
    </tr>
</table>

<br>
<br>


# Assessing Application Control

To assess the effectiveness of application control strategies:
- Identify authorised programs.
- Identify the application control approach that is being used (if in place).
- Assess the controls using assessment methods and tools.
- Determine the associated maturity level.

# Assessment methods

Application control assessments are possible without tools, but the efficacy of the tests will be significantly reduced, and edge cases that malicious actors might exploit could be missed. For instance, these actors might deploy bespoke tools to enumerate weak paths in a system.

The ACSC provides guidelines and recommendations on the methods and tools that can be used to assess the control.

The only true way to test is to attempt execution in all locations against all file types.

`SysInternals AccessChk` application can be used to generate output of folder permissions, but this is only relevant, potentially, for Level 1.
## E8MVT
Tests application control policies by attempting to write and execute certain file types in specific locations.

Also checks for MSFT recommended block rules and drive block rules are implemented.
## ACVT
tests application control policy by enumerating all sub-directories and attempts to write and execute each of the relevant file types from each location.

## Scripts

### Get AppLocker Policies

```powershell
Get-AppLockerPolicy -Effective -Xml | Set-Content ('c:\windows\temp\curr.xml')`
```

```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\*.exe -User Everyone
```

Test in calc.exe or notepad.exe:

```powershell
Test-AppLockerPolicy -XMLPolicy C:\windows\temp\curr.xml -Path C:\windows\system32\calc.exe, C:\windows\system32\notepad.exe -User Everyone
```
<br>
<br>

### Sysinternals accesschk

If only trusted Microsoft tools are permitted on the system, **SysInternals AccessChk** can be used for outputting folder permissions, noting this is only suitable for a path-based approach to implementing the control.

```powershell
accesschk -dsuvw [path] > report.txt
```

Running `whoami /groups` would also need to be executed to determine which user groups a typical standard user belonged to in order to determine the effective permissions for each path.

This approach is, however, likely to be tedious in assessing effectively.
<br>
<br>

# Maturity Level 1 guidance

The intent of application control at Maturity Level 1 can be met without a dedicated application control solution. This is achieved through file system permissions to prevent unnecessary access to user profile directories and temporary folders.

>***The execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets is prevented on workstations from within standard user profiles and temporary folders used by the operating system, web browsers and email clients*.**

Given how complex file system permissions can become, to effectively check application control it's essential to attempt to write and execute from all user-accessible directories. 
 
ACSC's Essential Eight Maturity Verification  (E8MVT) and Application Control Verification (ACVT) tools (available to ACSC partners) can assist in achieving this. A number of other tools on the market are also capable enumerating a file system to perform this test.

Where applicable, PowerShell cmdlets can be used to test and review AppLocker policies and Sysinternals acesschk can be used if only Microsfot-based tools are avaialble.

For a system on which tools cannot be run, and assuming a path-based approach is used, screenshots of the 'effective access' permissions for specified folders can be requested. This, however, has limitations because unless screenshots of access permissions are requested for every folder and sub-folder (for which there are usually many), it will not be possible to comprehensively assess whether read, write and execute permissions exist for a given user. Consequently, this will likely impact the quality of evidence cited in the final report.

At a minimum, screenshots for key paths (such as temporary folders used by the operating system, web browsers and email clients) should be requested and examined to determine whether inheritance is set, noting that at any point in a path, application control inheritance previously set by an operating system may be disabled by an application installer

# Maturity Level 2 guidance

Whereas ML1 is focussed on EUC endpoints, ML2 extends application control to internet-facing servers and includes additional log-retention requirements.
# Maturity Level 3 guidance

ML3 builds on ML2 in that it requires monitoring of logs, application control on *all* servers, and the implementation of Microsoft's block rules. Application control rulesets also need to be validated no less than annually.
<br>
<br>

# Other information

## Considering Kernel
Modern computers split virtual memory into kernel and user space. The scope to which an application control solution protects a system's kernel should be considered.
## Identifying adversary attempts to execute malicious code

Application control can help identify attempts to execute malicious code.

This can be achieved by configuring application control to generate event logs for allowed and blocked executions.

Event logs should included relevant information such as:
- name of the file
- date/time stamp
- username of the executing user

Application control logs can also ingest into a SIEM/SOAR system to allow for and contribute to broader context about the threat landscape.

## AppLocker and WDAC
  
AppLocker and Windows Defender Application Control (WDAC) are both security features in Windows, designed to control application usage and restrict unauthorised software. However, they have distinct differences:

1. **Design and Purpose**:
    - **AppLocker**: Primarily aimed at providing administrators with the ability to specify which users or groups can run particular applications, based on unique identities of files. It's more about managing application access than outright security.
    - **WDAC**: Focuses more on security. It is designed to prevent malware and untrusted applications from running by enforcing code integrity policies.
      
2. **Scope and Control**:
    - **AppLocker**: Works at a more granular level, allowing control over scripts, executable files, Windows Installer files, DLLs, and packaged app installers.
    - **WDAC**: Controls the entire spectrum of executable code on the system, including kernel mode drivers and user mode applications.
    
3. **Implementation and Management**:
    - **AppLocker**: Managed through Group Policy, making it easier to implement in an environment already using Group Policy for configurations.
    - **WDAC**: Managed through PowerShell and uses a different policy format, which can be more complex to set up but offers a higher level of security.
    -
4. **Flexibility and Usability**:
    - **AppLocker**: Offers more flexibility and is simpler to configure, especially for smaller organizations or those with less complex needs.
    - **WDAC**: While it provides a stronger security posture, it can be more challenging to implement and manage, particularly in environments with diverse applications.
    
5. **System Requirements**:
    - **AppLocker**: Available on Windows 7 and newer versions but only for Enterprise and Ultimate editions.
    - **WDAC**: Available on Windows 10 and Windows Server 2016 and later, offering broader support across different Windows editions.
    
6. **Security Level**:
    - **AppLocker**: Considered less robust in terms of security compared to WDAC, as it lacks the more comprehensive system-wide controls.
    - **WDAC**: Provides a more secure environment by ensuring that only trusted software runs on the system.

In summary, while AppLocker is more user-friendly and easier to manage, particularly for application access control, WDAC offers a more comprehensive and secure approach, focusing on system integrity and malware prevention. The choice between the two would depend on the specific needs and capabilities of the organisation, particularly in terms of desired security level and ease of management.

# Useful resources
- <a href="https://learn.microsoft.com/en-us/compliance/essential-eight/e8-app-control">Essential Eight application control - Essential Eight | Microsoft Learn</a>
- <a href="https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules">Microsoft recommended driver block rules - Windows Security | Microsoft Learn</a>
- <a href="https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac">Applications that can bypass WDAC and how to block them - Windows Security | Microsoft Learn</a>
- <a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/small-business-cyber-security/small-business-cloud-security-guide/technical-example-application-control">Technical example: Application control | Cyber.gov.au</a>
