---
layout: post
title:  "Maquina Traverxec de TryHackMe (No necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de TryHackMe llamada TRAVERXEC
tags: TryHackMe, Ftp, Smb, CurlFtp, Web Hacking, , SUID, Writeup, 
---

# Traverexec ~ TryHackMe

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.165     "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Usamo la herramienta `Whatweb`
```bash
└─# whatweb http://10.10.10.165                                                                                                                                                                                1 ⚙
http://10.10.10.165 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[nostromo 1.9.6], IP[10.10.10.165], JQuery, Script, Title[TRAVERXEC]
```
Procedemos a hecharle un vistazo visual a la web
```bash
# Datos Relevantes encontrados:
Version y servicio : nostromo 1.9.6 
Nombre de usuario a nivel web: David White
```
Hacemos una busqueda en Searchsploit de Nostromo 1.9
```bash
# searchsploit nostromo 1.9   
-------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------
nostromo 1.9.6 - Remote Code Execution                                                                              | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution                                                | linux/remote/35466.sh
-----------------------------------------------------------------------------------------------------------------------------------------------------
```
Investigamos para ver lo que nos hace el exploit que no funciona en python3, para seguir la misma metodologia manualmente.
  

