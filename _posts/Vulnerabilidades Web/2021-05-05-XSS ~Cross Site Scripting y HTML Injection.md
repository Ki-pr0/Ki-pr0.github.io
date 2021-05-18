---
layout: post
title:  "Aprendiendo sobre ataques XSS y HTML Injection"
description: Aprendiendo sobre las Vulnerabilidades " XSS// HTML INJECCTION "
tags: Web Attacks xss html injecction
---
Seguimos aprendiendo las principales Vulnerabilidades a nivel Web mas Basicas
  
# ~ XSS ~ CROSS SITE SCRIPTING

1.- El XSS del que hablaremos hoy, es una vulnerabilidad en la que el hacker ataca a otros usuarios que se conectan a dicha página web y los ataca en busca de varias cosas: 
secuestrarles la sesión, robarles la contraseña o cualquier otra información que considere de interés.

- Cómo funciona el Cross Site Scripting:
``` 
Existen dos tipos: 
    * directa o persistente 
    * indirecta o reflejada
```
En ambos casos, el atacante malicioso inyecta código sobre algún campo de entrada de datos que ofrezca la página web,
bien sea este la típica cajita con el icono de la lupa para búsqueda de palabras clave, un recuadro de espacio de participación en un foro, o un formulario de recogida de datos.

# Cross Site Scripting persistente
Si el código que hemos insertado se queda almacenado en el servidor, por ejemplo formando parte de una contribución en un foro,
el ataque se dice que es persistente. Cualquier usuario que entre a leer dicha contribución leerá el texto inocente pero probablemente no así el código inyectado,
que sin embargo sí será interpretado por el navegador del visitante, ejecutando las instrucciones que el hacker haya definido.

El atacante no puede predecir el usuario que va a caer en la trampa.

# Cross Site Scripting reflejado
Pero si el código que insertamos no se queda almacenado en la web, sino que va embebido dentro de un enlace que se hace llegar de algún modo a la víctima para que pinche en él,
se dice que este tipo de ataque es reflejado. Se llama así porque, si finalmente la víctima pincha en el enlace, el navegador le llevará a la página en cuestión,
que normalmente es un sitio legal donde el usuario tiene cuenta abierta, y a continuación ejecutará el código embebido, el cual intentará robarle la “cookie” de la sesión,
o los datos que introduzca en el formulario, o incluso podrá desencadenar acciones más sofisticadas en su PC.

Pero la característica diferencial con el anterior ataque es que en este caso en el servidor web no queda almacenado nada.

# HTML Injection
La inyección de HTML es un tipo de vulnerabilidad de inyección que se produce cuando un usuario puede controlar un punto de entrada y puede inyectar código HTML arbitrario en una página web vulnerable.
Esta vulnerabilidad puede tener muchas consecuencias, como la divulgación de cookies de sesión de un usuario que podrían usarse para hacerse pasar por la víctima o, de manera más general,
puede permitir que el atacante modifique el contenido de la página visto por las víctimas.

Existe una amplia gama de métodos y atributos que se pueden utilizar para representar contenido HTML.
Si estos métodos se proporcionan con una entrada que no es de confianza, existe un alto riesgo de vulnerabilidad de inyección de HTML.
Por ejemplo, se puede inyectar código HTML malicioso a través del innerHTMLmétodo JavaScript, que generalmente se usa para representar código HTML insertado por el usuario.
Si las cadenas no se desinfectan correctamente, el método puede habilitar la inyección de HTML.
Una función de JavaScript que se puede utilizar para este propósito es document.write().
