---
title: "TheNotebook - HackTheBox"
layout: single
excerpt: "Esta es una máquina de dificultad media, para la intrusión mediante la cookie logre saber que estaba tratando con un ataque JWT, para romperlo me cree una cookie nueva tirando desde mi clave privada por un servidor por Python y cambio de panel, tenía una opción de subir de archivos, cree una reverse Shell y la subí, para la escalada de privilegios me aproveche de una versión vulnerable de Docker."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/127784478-22759c0e-2a0d-4735-b467-ccb39e2e8b18.png"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - PHP
  - Docker
  - JWT
  - SSH
---

![image (35)](https://user-images.githubusercontent.com/69093629/129931228-f352f4a7-ecdb-49ef-9786-099fcce0e627.png)

Comencé haciendo un escaneo con `Nmap` para detectar puertos abiertos.

```bash 
┌──(root💀kali)-[/home/wackyh4cker/HTB/TheNotebook]
└─# nmap -sS --min-rate=5000 --open -v -n 10.10.10.230 -oN targeted
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-31 19:12 CEST
Initiating Ping Scan at 19:12
Scanning 10.10.10.230 [4 ports]
Completed Ping Scan at 19:12, 0.08s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 19:12
Scanning 10.10.10.230 [1000 ports]
Discovered open port 80/tcp on 10.10.10.230
Discovered open port 22/tcp on 10.10.10.230
Completed SYN Stealth Scan at 19:12, 0.47s elapsed (1000 total ports)
Nmap scan report for 10.10.10.230
Host is up (0.15s latency).
Not shown: 997 closed ports, 1 filtered port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds
       	Raw packets sent: 1014 (44.592KB) | Rcvd: 1009 (40.356KB)
```

Hice otro para detectar la versión de cada puerto abierto encontrado.

```bash
┌──(root💀kali)-[/home/wackyh4cker/HTB/TheNotebook]
└─# nmap -sC -sV -p22,80 10.10.10.230 -oN webscan             	 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-31 19:12 CEST
Nmap scan report for 10.10.10.230
Host is up (0.069s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp open  http	nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.04 seconds
```

Tenía dos puertos abiertos, empece mirando por el servidor web, esto es lo que tenía.

![PaginaPrincipal](https://user-images.githubusercontent.com/69093629/127784555-be9394f6-a112-45ac-b968-e899bfe8c4af.png)

Me registré y me redirigió a este panel.

![accesoalpanel](https://user-images.githubusercontent.com/69093629/127784565-718e0d46-ffd0-434e-9970-739318080035.png)

Cree una nota y probé distintas inyecciones de código `html` y `js` pero no era vulnerable a `XSS` o `HTMLi`, probé a interceptar la petición para ver como va todo por detrás y encontré una cookie que me llamo la atención.

![jwtcookie](https://user-images.githubusercontent.com/69093629/127784626-d6684b12-cd00-4841-a60d-cda619895db7.png)

Al parecer era un `JWT` o "JSON Web Token", copie la cookie y la pegue en [jwt.io](https://jwt.io) para ver el formato `json` como se estaba tratando y encontré lo siguiente.

![jwtio](https://user-images.githubusercontent.com/69093629/127784670-55e9afce-d921-48ee-8db2-f2cde7935c9b.png)

Al parecer se estaba comunicando con una `priv key` en `localhost`, es decir que no tenía ningún tipo de acceso a ella, pensé en crear la mía propia con `OpenSSL` y que tire por la mía abriendo un servidor por `Python`, empecé creando la clave privada con el siguiente comando.

```bash
openssl genrsa -out privKey.key 2048
``` 

Abrí un servidor por `python` por el puerto por el que corría la `priv key` de la víctima, el `7070`, y cambie a mi dirección `IP` y puse `1` en `admin_cap` y pegue la mi `priv key` abajo a la izquierda.

![codigo ](https://user-images.githubusercontent.com/69093629/127784840-d48b22b0-a2a6-4aac-a821-1bf7a629f685.png)

Copie la cadena en `base64` y la sustitui por la cookie que me venía en la página.

![paneladminconseguido](https://user-images.githubusercontent.com/69093629/127784916-d01dd378-0ac6-4cb2-9ee1-7d5a494add28.png)

Y cambio el panel, ahora había una sección que me permitía subir archivos.

![uploadfiles](https://user-images.githubusercontent.com/69093629/127784939-95aaa155-21b1-4328-98ee-66c58794d699.png)

Inmediatamente probé a subir una `reverse shell` en PHP, utilice una de `pentestmonkey`.

![subida](https://user-images.githubusercontent.com/69093629/127784972-88b14e18-19fb-45fc-9e7a-e2a5aea08dc0.png)

Me dejo subirla, le di a `save` con una sesión de `netcat` corriendo por el puerto '443' y gané acceso a la máquina.

![reverseshell (1)](https://user-images.githubusercontent.com/69093629/127785005-a0a7153c-f609-4079-8ba6-ab006cff7e60.png)

Hice un tratamiento de la `TTY`, investigando un poco en la máquina encontré un archivo llamado `home.tar.gz` que me llamo la atención, por lo que pensé en transferírmelo a mí máquina con `netcat`.

![transferusingnmap](https://user-images.githubusercontent.com/69093629/127785044-0f98c96a-e111-4c53-bb96-4878f3e6057f.png)

Descomprimiéndolo vi que era el directorio `home`, dentro encontré una clave privada de `SSH`, una `id_rsa`, también tuve que enumerar el usuario en el que tenía que migrar y en la ruta que seguí encontré un directorio llamado `noah`.

![ypadentroconhome](https://user-images.githubusercontent.com/69093629/127785072-76c5a770-7284-47a9-ba7e-a8300a94fec1.png)

Le di permisos `600` a la `id_rsa` y probé a conectarme con ella en `SSH` haciendo uso del usuario `noah` y funciono.

![ssshacceso](https://user-images.githubusercontent.com/69093629/127785391-bec76498-0971-405a-9f70-2c52ce270879.png)

Ya pude visualizar la "flag" del usuario.

![flagdelusuario (3)](https://user-images.githubusercontent.com/69093629/127785441-cdc9b061-7d1b-4a08-b252-ae66a8e78296.jpg)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

Ahora solo faltaba la escalada de privilegios, haciendo `sudo -l` vi que podía ejecutar Docker con privilegios de `sudo`.

![sudoguionele](https://user-images.githubusercontent.com/69093629/127785458-6b7c09ad-a0c9-49d2-924c-99da531f2a12.png)

Lo ejecuté añadiendo `bash` y conseguí una sesión con Docker, pero esto no era la escalada, ya que solo estaba en un contenedor, mire la versión de Docker.

![dockerversion](https://user-images.githubusercontent.com/69093629/127785504-8970f5a3-4746-4710-8e71-e1837766edc3.png)

Busque si había algún exploit de esa versión en Google y encontré el siguiente `PoC`.

![pocdockerexploit](https://user-images.githubusercontent.com/69093629/127785520-25394cde-7733-416a-9ec6-f9bf94b0f215.png)

Me lo traje y a mí máquina y modifique la línea que hacia la ejecución de código, puse que le dé permisos `777` al `/etc/passwd`.

![modificandoetchosts](https://user-images.githubusercontent.com/69093629/127785669-327b2f5d-b0c4-4b7b-af24-403bf5e4ab4e.png)

Compile el exploit y lo transferí al servidor víctima, concretamente en la sesión de Docker, ejecute el exploit corriendo otra sesión de Docker a la vez que se esté ejecutando el exploit.

![descargarexploit (1) (1)](https://user-images.githubusercontent.com/69093629/127785892-1faeee6d-f798-4dad-9b86-6d4eadca10e4.png)

Modifique la `x` del `/etc/passwd` y puse una contraseña creada anteriormente con `OpenSSL`, hice `sudo su` y puse la contraseña que me creo `OpenSSL` y gane acceso con `root`, ya pude ver la "flag".

![bashmenosoe (1)](https://user-images.githubusercontent.com/69093629/127785688-60e6f17c-073c-4f7e-9139-9387f8cb17a4.png)












