---
layout: post
title:  "Maquina Retirada Inception de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada INCEPTION
tags: HTB, dompdf, Remote File Read, squidproxy, webdav, CronTabs, Web Hacking, Maquinas Retiradas, Writeup
---

# Inception ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$ nmap -p- --open -sS --min-rate 5000 -Pn -n -vvv 10.10.10.67
```
Realizamos el segundo escaneo para averiguar la version y servicios en los puerto abiertos
```bash
$ nmap -sC -sV -p80,3128 -Pn -n -v 10.10.10.67

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
```

