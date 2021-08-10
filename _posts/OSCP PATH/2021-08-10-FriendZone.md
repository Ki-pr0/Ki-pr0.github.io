---
layout: post
title:  "OSCP Path ~ FriendZone Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada FRIENDZONE siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, Transferencia de Zona, Multiples Dominios, CRON, LFI, Maquinas Retiradas, Writeup, Hacking
---

# FriendZone ~ Hack The Box to OSCP

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.123       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT      STATE SERVICE VERSION
