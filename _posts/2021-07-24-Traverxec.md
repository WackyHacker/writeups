---
title: "Traverxec - HackTheBox"
layout: single
excerpt: "Esta es una máquina fácil, para su intrusión encontré una versión vulnerable de un servicio que estaba corriendo la máquina, llamado nostromo, use un exploit de GitHub para esa versión y gane la ejecución de código arbitrario, para la escalada de privilegios me aproveche de una utilidad que podía ejecutar como el usuario root, tuve que minimizar la terminal para hacer el bypass."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/126876755-6309d046-4662-44f8-b4ba-8c74e6bd84ee.png"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - nostromo 1.9.6
  - journalctl 
  - id_rsa
  - public_www
---

![image (29)](https://user-images.githubusercontent.com/69093629/126876755-6309d046-4662-44f8-b4ba-8c74e6bd84ee.png)

Empece haciendo un escaneo con `Nmap` para detectar puertos y servicios abiertos.

```bash 
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ nmap -sS --min-rate=5000 --open -v -n 10.10.10.165 -oN targeted
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-24 17:42 CEST
Initiating Ping Scan at 17:42
Scanning 10.10.10.165 [4 ports]
Completed Ping Scan at 17:42, 0.09s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:42
Scanning 10.10.10.165 [1000 ports]
Discovered open port 80/tcp on 10.10.10.165
Discovered open port 22/tcp on 10.10.10.165
Completed SYN Stealth Scan at 17:42, 0.67s elapsed (1000 total ports)
Nmap scan report for 10.10.10.165
Host is up (0.052s latency).
Not shown: 998 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.96 seconds
       	Raw packets sent: 2002 (88.064KB) | Rcvd: 4 (156B)
```

Efectúe otro escaneo para verificar la versión y servicio de cada puerto encontrado.

```bash 
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ nmap -sC -sV 10.10.10.165 -oN webscan                     	 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-24 17:42 CEST
Nmap scan report for 10.10.10.165
Host is up (0.051s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http	nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.42 seconds
```

Vi que el servidor web corría un servicio llamado `nostromo`, eso me llamo la atención por lo que recurrí a ver si había alguna versión vulnerable y encontré el siguiente exploit.

![Captura de pantalla (659)](https://user-images.githubusercontent.com/69093629/126877395-67a38c00-0e95-44ca-8aea-3c5ae5e33910.png)

Su uso fue sencillo, le especifiqué la IP y el puerto por dónde corría el servidor y el comando que quería ejecutar.

![rce](https://user-images.githubusercontent.com/69093629/126877425-672ccd58-f4e1-4a0d-a530-4eb42dc8d553.png)

Ya tenía la ejecución de código arbitrario, me entablé un Shell inverso por el puerto 443 haciendo uso de `mkfifo`.

![mkfifo](https://user-images.githubusercontent.com/69093629/126877472-1b4ea9dd-c8f0-4423-803c-34cc5914e72a.png)

También hice un tratamiento de la `TTY` para tener un full Shell interactivo y manejarme más cómodamente.

![tratamiento de la tty](https://user-images.githubusercontent.com/69093629/126877763-ab10f4a5-d16c-4a53-af02-9c784d9e4ef3.png)

Tras una pequeña investigación logré encontrar un archivo que me dio mucha información para el siguiente paso.

![archivo](https://user-images.githubusercontent.com/69093629/126877546-9d3cd5b1-8414-4708-b87c-6bad7cba8238.png)

Primero le hice un cat a una ruta que me reportaba que me llamo la atención, tenía una credencial hasheda, la crackee con `john the ripper`.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 SSE2 4x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me   	(david)
1g 0:00:03:19 DONE (2021-07-24 18:02) 0.005009g/s 52994p/s 52994c/s 52994C/s Noyoudo..November^
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
 
Pensé que era la contraseña del usuario `david` pero no, viendo el archivo también me reportaba un `public_www`, tras una búsqueda en `Google` logre dar con la conclusión de que se trataba de un directorio en el servidor web, pude acceder desde la Shell que ya tenía y encontré un archivo llamado `backup-ssh-identity-files.tgz`.

![backups](https://user-images.githubusercontent.com/69093629/126877684-859b5c6d-ce93-4a5f-a897-6f245d1d18e5.png)

Me lo transferí con `netcat` para ver que es lo que tenía.

![usandonetcat](https://user-images.githubusercontent.com/69093629/126877698-e6f127bc-f123-4cf1-bc1f-1c657c0f575d.png)

Lo descomprimí con `7z` y encontré una `id_rsa`, una clave de acceso a `ssh`.

![id_rsa](https://user-images.githubusercontent.com/69093629/126877810-4e2bb17a-6b1e-41e8-a284-74baf5c16b40.png)

Pero estaba encriptada por contraseña.

![id_rsaimagen](https://user-images.githubusercontent.com/69093629/126877827-b77756fd-262a-416a-8b0e-b1068a0aeaf4.png)

Para crackear su contraseña hice uso de la utilidad `ssh2john` que me extrajo su `hash` equivalente.

![ssh2john](https://user-images.githubusercontent.com/69093629/126877843-6278676c-ba96-4479-b101-cd4b618f9184.png)

Copie el `hash` en un archivo llamado `hashs` y lo crackee con `john the ripper`.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ john --wordlist=/usr/share/wordlists/rockyou.txt hash2                         	1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter       	(?)
1g 0:00:00:07 DONE (2021-07-24 18:33) 0.1412g/s 2025Kp/s 2025Kc/s 2025KC/sa6_123..*7¡Vamos!
Session completed
```

Me la consiguió crackear, le di permisos 600 a la `id_rsa` y accedí con ella haciendo uso de la contraseña crackeada, ya pude visualizar la "flag" del usuario.

![flagdelusuario](https://user-images.githubusercontent.com/69093629/126877894-9e3ee2db-8068-4d07-a07c-f70c1a72d844.jpg)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

Para la escalada de privilegios encontré un script llamado `server-stats.sh` que ejecuta `journalctl` con privilegios de `sudo`.

![scriptjournal](https://user-images.githubusercontent.com/69093629/126877934-04d8043d-2028-4b83-be0c-65cdc24ae5f8.png)

Me dirigí a [gftobins](https://gftobins.github.io) y filtré por `journalctl` para ver si podía aprovecharme para escalar.

![sudoengftobins](https://user-images.githubusercontent.com/69093629/126877969-0b373f52-acae-485f-9e13-c69095c274b1.png)

Al parecer sí, lo que hice fue ejecutar `journalctl` seguido de la sintaxis del script y eliminando el `/usr/bin/cat` porque tenía que ser en formato `lees` o `more`, minimice la terminal y escribí `!/bin/sh` y me convertí en `root`, ya pude visualizar la "flag".

![rut (1)](https://user-images.githubusercontent.com/69093629/126878038-5de15da2-952c-48d8-86ec-b95c5554b370.jpg)















