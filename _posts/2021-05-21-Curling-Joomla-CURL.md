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
