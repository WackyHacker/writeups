---
title: "Armageddon - HackTheBox"
layout: single
excerpt: "Esta es una máquina fácil, para la intrusión me aproveche de una versión vulnerable de Drupal que estaba corriendo en el sistema y gane RCE, tuve que migrar a otro usuario, para ello encontré credenciales de MySQL que me sirvieron para encontrar un hash, tras romperlo la credencial era del usuario al que tenía que migrar, para la escalada de privilegios me aproveche de snap, ya que se podía ejecutar con privilegios de sudo."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/127804995-eba40d50-e9ad-43a8-bb7b-b88434fdad40.png"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - mysql
  - Drupal
  - snap
  - SSH
---

<p align="center">
<img src="https://user-images.githubusercontent.com/69093629/129924671-d8937044-7ee4-4b35-8791-7c8261d5d903.png">
</p>

Comencé efectuando un escaneo con `Nmap` para detectar puertos y servicios abiertos en el sistema.

```bash 
┌──(root💀kali)-[/home/wackyh4cker/HTB/Armageddon]
└─$ nmap -sS --min-rate=5000 --open -v -n 10.10.10.233 -oN targeted            	 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-29 18:59 CEST
Initiating Ping Scan at 18:59
Scanning 10.10.10.233 [4 ports]
Completed Ping Scan at 18:59, 0.07s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:59
Scanning 10.10.10.233 [1000 ports]
Discovered open port 22/tcp on 10.10.10.233
Discovered open port 80/tcp on 10.10.10.233
Completed SYN Stealth Scan at 18:59, 0.68s elapsed (1000 total ports)
Nmap scan report for 10.10.10.233
Host is up (0.094s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.97 seconds
       	Raw packets sent: 1825 (80.276KB) | Rcvd: 1811 (72.436KB)
 ```
 
 Hice otro escaneo para detectar la versión de cada servicio encontrado.
 
 ```bash 
┌──(root💀kali)-[/home/wackyh4cker/HTB/Armageddon]
└─$ nmap -sC -sV -p22,80 10.10.10.233 -oN webscan             	 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-29 19:00 CEST
Nmap scan report for 10.10.10.233
Host is up (0.037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http	Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.31 seconds
```

Vi que tenía un servidor web, le eche un vistazo.

![armageddon](https://user-images.githubusercontent.com/69093629/127578672-548a6401-10d7-430d-a01c-835523da332f.png)

Encontré un CMS de Drupal, pense en buscar si había algún exploit y encontré el siguiente.

![exploit](https://user-images.githubusercontent.com/69093629/127578743-4233e86c-f010-478e-96ec-558de362dbdf.png)

Lo ejecuté brindándole la URL del sitio web y me otorgo ejecución de código arbitrario.

![drupalgeddon2](https://user-images.githubusercontent.com/69093629/127578821-64748b45-715f-49ea-b03f-1a8a789a767a.png)

Ahora solo faltaba entablarse una reverse Shell para ganar acceso a la máquina, probé con una `reverse shel`' de `bash` pero me detectaba un "bad character", por lo que tuve que hacer uso de una de `python`.

![entrada](https://user-images.githubusercontent.com/69093629/127578935-84be425c-c97e-4f50-9415-c7ce2b71ce73.png)

Y recibí una conexión por `netcat`

![reverseshell](https://user-images.githubusercontent.com/69093629/127578974-241fd99f-8b3f-4783-80d6-ac0d648f7737.png)

Tras una pequeña investigación en `Google` encontré que se guardan credenciales en un archivo llamado `settings.php`.

![credencialesdrupal](https://user-images.githubusercontent.com/69093629/127579080-1bfebdce-534d-4b71-81e1-1f2f3992d6e4.png)

Hice un filtrado por ese archivo con `find` y encontré credenciales

![drupalcreds](https://user-images.githubusercontent.com/69093629/127579123-79d4bb64-5c8c-4d18-8ad7-fb7e86012ce8.png)

Era un usuario y una contraseña, probé en `SSH` pero no funciono, pero cuando probé en `mysql` si funciono, pero se me quedaba colgado, por lo que tuve que ejecutar la sentencia en un mismo comando, probé a listar las tablas.

![tables](https://user-images.githubusercontent.com/69093629/127579240-4228535d-4557-45ec-bcbf-81f197f88ba5.png)

La tabla `users` me llamo la atención por lo que seleccione `name` y `pass` de la columna `users` y me reporto un `hash`. 

![hashdecontra (1)](https://user-images.githubusercontent.com/69093629/127579502-c8690364-ef70-4c36-a0bd-6f458cf0f5f3.png)

Lo pude crackear por fuerza bruta con `john`.

```bash
┌──(root💀kali)-[/home/wackyh4cker/HTB/Armageddon/Drupalgeddon2]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash                                                                                                	 
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo       	(?)
1g 0:00:00:01 DONE (2021-07-29 20:00) 0.7407g/s 171.8p/s 171.8c/s 171.8C/s courtney..harley
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Esta credencial me autentico por `SSH` haciendo uso del usuario del sistema `brucetherealadmin`.

![sshypadentro](https://user-images.githubusercontent.com/69093629/127580332-0e65c9f8-28cd-451f-8e50-314742db01f9.png)

Ya pude visualizar la "flag" del usuario.

![flagdelusuario (2)](https://user-images.githubusercontent.com/69093629/127579644-4ec95b78-ef93-4fa2-b47b-f5694ec3cac3.jpg)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

Para la escalada de privilegios me permitía ejecutar `snap` con permisos `sudo`, busque en [gtfobins](https://gtfobins.github.io) y encontré que me podía aprovechar haciendo uso de `sudo`.

![Captura de pantalla (661)](https://user-images.githubusercontent.com/69093629/127579819-ada222e3-d01a-4b9f-bbe1-aeb66e3aedae.png)

Al ejecutar un comando me dio un problema que pude solucionar instalando la gema correspondiente. 

```ruby
┌──(root💀kali)-[/home/wackyh4cker/HTB/Armageddon/Drupalgeddon2]
└─$ gem install fpm
```

Ahora si me dejo crear el archivo `.snap` malicioso en mí máquina, hice que se ejecute `cat /root/root.txt` para ver la "flag" de `root`.
        
![verlaflag](https://user-images.githubusercontent.com/69093629/127580026-55b17835-313b-4377-807b-9492dca7ca03.png)

Una vez exportado a la maquiná víctima hice uso del comando que me permitia ejcutar `snap` con prilegios de `sudo` y seleccionando mi `.snap` seguido de los parametros `--dangerous` y `--devmode` y me reporto la "flag" en texto claro.

![laflag](https://user-images.githubusercontent.com/69093629/127580209-10840b2e-8a23-477f-a3aa-1a582f79aab1.jpg)




