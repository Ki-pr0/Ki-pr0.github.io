---
layout: post
title:  "Ataques CSRF Y SSRF"
description: Explicacion de los Ataques Cross Site Requests Forgery y Server Side Requests Forgery
tags: CSRF & SSRF Attacks
---

# Ataque Cross Site Request Forgery ~ (CSRF) ~ Maquina HTB SecNotes

CSRF: el Cross Site Request Forgery (CSRF o XSRF) es un tipo de ataque que se suele usar para estafas por Internet.
Los delincuentes se apoderan de una sesión autorizada por el usuario (session riding) para realizar actos dañinos.
El proceso se lleva a cabo mediante solicitudes HTTP.

El funcionamiento del CSRF es el siguiente: mientras el usuario está con la sesión iniciada en el portal, también visita otra página, la cual está creada por el hacker.
En esta otra página, el usuario realiza una acción cualquiera, por ejemplo, el accionamiento de un botón.
A continuación, el atacante envía una solicitud HTTP al portal empleado por el usuario y
realiza una acción dañina en nombre del usuario, ya que la sesión sigue activa. 
Para conseguir todo esto, el atacante solo necesita conocer la solicitud HTTP correcta y esta solicitud es bastante fácil de leer.

El servidor del portal reconoce que la solicitud HTTP ha sido formulada correctamente y a través de las cookies correspondientes, también detecta que el usuario (o su navegador) permanecen con la sesión iniciada.
El servidor ejecuta la acción y es posible que el usuario ni se dé cuenta de que se acaba de llevar a cabo una acción en su nombre.
```bash
"El ataque CSRF funciona porque el servidor receptor no comprueba de dónde procede la solicitud."
"Es decir, no queda claro si la solicitud HTTP ha sido creada por la propia página web o si su origen es externo."
"En este contexto, el atacante se aprovecha de una laguna de seguridad del navegador; transmite las solicitudes sin evaluar las consecuencias."
``` 

# Cómo explotar un SSRF (Server Side Request Forgery) y hacer un XSPA (Cross Site Port Attacks)

Las vulnerabilidades SSRF (Server Side Request Forgery) y los ataques de XSPA (Cross Site Port Attacks) son dos fallos de seguridad que van casi siempre de la mano. Los bugs de SSRF se producen en aplicaciones web inseguras que permiten a un atacante forzar al servidor web a realizar peticiones desde dentro del sistema hacia el exterior. Usando esas conexiones, los ataques de XSPA tratan de conocer, en base a las respuestas obtenidas, la lista de puertos que se encuentran abiertos o por el contrario cerrados en el servidor al que se fuerza la conexión.

Estas vulnerabilidades afectan al Back-End y que vienen conducidas por una mala validación en el Front-End o API al poder ser manipuladas las direcciones a las que se le van a realizar peticiones desde el Back-End. La principal ventaja para un atacante de que las peticiones sean realizadas desde dentro de la red en la que se encuentra el sistema vulnerable es que le van a permitir acceder a sitios que de otra manera no podría (pivoting), tal como sucede cuando estamos conectados a nuestro router y podemos acceder a las maquinas conectadas a nuestra red local.

```bash
Agradecemos toda la info a Chema Alonso "https://www.elladodelmal.com/2015/04/ssrf-server-side-request-forgery-xspa.html"
```
# SSRF & XSPA en buscadores y paneles de administración con CSPP 

Estos fallos son muy típicos, y ya los hemos visto en un buen número de sitios. En el artículo de Buscadores como arma de destrucción masiva se hablaba de posibles ataques de SSRF utilizando la indexación maliciosa o los agregadores de noticias, que permitían por ejemplo que un servidor lanzara un ataque de SQL Injection sin interacción alguna del atacante

--- Buscadores como arma de destruccion massiva:
 ```bash
"https://www.elladodelmal.com/2010/05/buscadores-como-arma-de-destruccion.html"
``` 
Un caso curioso de SSRF son los paneles de administración expuestos en Internet, como sitios de configuración de impresoras HP que permiten escanear la DMZ completa, o los casos de bugs de Connection String Parameter Polution, tanto de bases de datos MySQL como de tecnologías .NET. Con ellos hemos visto lo fácil que es realizar ataques de XSPA (Cross Site Port Attacks) aprovechando estas vulnerabilidades de SSRF

