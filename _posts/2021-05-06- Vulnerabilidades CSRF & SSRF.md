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
En este contexto, el atacante se aprovecha de una laguna de seguridad del navegador; transmite las solicitudes sin evaluar las consecuencias.
``` 
