---
layout: post
title:  "Aprendiendo a identificar los diferentes ataques basicos a nivel Web"
description: Aprendiendo sobre las Vulnerabilidades " SSTI - Servidores que funcionan con Flask, PythonServers "
tags: Web Attacks
---
Empezaremos por aprender las principales Vulnerabilidades a nivel Web
  
# ~ STTI ~   Server Side Template Injection


What is a SSTI Injection?

A server-side template injection occurs when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

See here for further information.

We are provided with a list of payloads:
```bash
{{7*7}}
```
```bash
${7*7}
```
```bash
<%= 7*7 %>
```
```bash
${{7*7}}
```
```bash
#{7*7}
```

Chequear PayloadsAllTheThings para mas Payloads.
