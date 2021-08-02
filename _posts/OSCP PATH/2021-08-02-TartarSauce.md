---
layout: post
title:  "OSCP Path ~ TartarSauce de Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada TTARTARSAUCE siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, Wordpress, Wpscan, Plugins, Gwolle, tar, python, Maquinas Retiradas, Writeup, Hacking
---

# TartarSauce ~ Hack The Box to OSCP

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.88       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
