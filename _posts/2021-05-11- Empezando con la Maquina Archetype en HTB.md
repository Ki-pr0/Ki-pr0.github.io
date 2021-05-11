---
layout: post
title:  "Maquinas para empezar en HTB"
description: En esta ocasion empezaremos con los Writeups de las maquina de StartingPoint  de HackTheBox
tags: HTB, Empezando, Hacking, Starting
---

# Archetype ~ Hack The Box

Comprobamos que la maquina este activa con una traza ICMP, usamos la herramienta PING.
```bash
 "# ping -c 10 10.10.10.27"                                       
PING 10.10.10.27 (10.10.10.27) 56(84) bytes of data.
64 bytes from 10.10.10.27: icmp_seq=1 ttl=127 time=39.4 ms
64 bytes from 10.10.10.27: icmp_seq=2 ttl=127 time=39.5 ms
^C
--- 10.10.10.27 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 39.430/39.449/39.469/0.019 ms
```
La maquina esta activa y por el ttl identificamos que puede es WINDOWS

# Enumeracion con Nmap 

Procedemos a enumerar todos los puertos abiertos en un escaneo usando los siguiente parametros:

```bash
 "nmap -p- --open -T5 -v -n -Pn [IP VICTIMA]" 
```  
 Si en la maquina victima el escaneo con Nmap va lento..
 Usamos el siguiente escaneo:
 
```bash
 "nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn "[IP VICTIMA]" -oG allports"
```
Con la funcion de extractPorts: filtramos por los puertos abiertos pasandole el archivo de salida del primer escaneo con Nmap

```bash
# extractPorts allports

[*] Extracting information .......

        [*]IP ADDRESS: 10.10.10.27
        [*]OPEN PORTS: 135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669

```
 2.- Siguiente Escaneo con Nmap
 
Procedemos a escanear la version y servicios de los puerto encontrados como abiertos:

```bash
nmap -sC -sV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669 -oN Target 10.10.10.27
```
Output:

```bash
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-03-16T16:48:45
|_Not valid after:  2051-03-16T16:48:45
|_ssl-date: 2021-03-16T17:55:06+00:00; +17m25s from scanner time.
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h41m26s, deviation: 3h07m50s, median: 17m25s
| ms-sql-info: 
|   10.10.10.27:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-03-16T10:54:52-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-16T17:54:54
|_  start_date: N/A
```
Encontramos iformacion util para proseguir con las siguiente herramienta

Utilizamos la siguiente herramienta para ver si tenemos acceso al servicio samba sin proporcionar contraseña (-N) y ver si hay algun recurso disponible, descargarlo, subir algun archivo etc.
smbclient
```bash
smbclient -N -L //10.10.10.27/
```

mssqlclient.py

```bash
mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth
```
