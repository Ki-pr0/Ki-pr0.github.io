---
layout: post
title:  "Maquinas para empezar en HTB"
description: En esta ocasion empezaremos con los Writeups de las maquina de StartingPoint  de HackTheBox
tags: HTB, Empezando, Hacking, Starting
---

# Archetype

--- Enumeracion ---
1.- Primer Escaneo con Nmap

Procedemos a enumerar todos los puertos abiertos en un escaneo usando los siguiente parametros:

```bash
 "nmap -p- --open -T5 -v -n -Pn [IP VICTIMA]" 
```  
 Si en la maquina victima el escaneo con Nmap va lento..
 Usamos el siguiente escaneo:
 
```bash
 "nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn "[IP VICTIMA]" -oG allports"
 ```
 
 2.- Segundo Escaneo con Nmap
 
 Procedemos a escanear la version y servicios de los puerto encontrados como abiertos
```bash
nmap -sC -sV -p
```
Foto
