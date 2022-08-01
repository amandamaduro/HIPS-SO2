# HIPS-SO2
Sistema de Deteccion y prevencion de intrusos basado en IPS host based desarrollado en Python y Flask, este sistema opera en Linux/CentOS 8. Desarrollado por: Amanda Maduro y Amparo Oliver
<details>
<summary markdown="span"> 

## Funciones
</summary>

  1. Verificar archivos binarios de sistema y modificaciones realizadas
     en el archivo /etc/passwd o /etc/shadow con el uso de la herramienta md5sum.
  2. Verificar usuarios conectados y desde que origen.
  3. Chequear si hay sniffers o si el equipo entro en modo promiscuo. 
  4. Revisar archivos log, detectando los accesos indebidos en el sistema.
  5. Verificar el tamaño de la cola de mails del equipo.
  6. Identificar procesos que consumen un porcentaje elevado de memoria.
  7. Verificar directorios /tmp, detectando archivos ejecutables que pueden ser sospechosos. 
  8. Contralar ataques de DDOS.
  9. Examinar archivos que esten ejecutandose como cron.
 10. Verificar intentos de accesos invalidos a la maquina. 
 
#### Medidas Preventivas:
       1. Matar procesos (kill)
       2. Bloquear IP's
       3. Cambiar contraseña de usuarios.
       4. Bloquear servicios de correo.
       5. Enviar archivos a cuarentena. 
			 
Cuando se genera una alerta o se toma una decision preventiva, esto queda registrado en los logs de *alarmas.log* y *prevencion.log*

</details>

<details>
<summary markdown="span">

## Requerimientos

</summary>

Para que el HIPS funcione correctamente se necesitan de configuraciones previas y la instalacion de algunas librerias de python.

### Python3 
Para instalar python3 ejecutamos:
```
sudo yum install python3 -y
```
### PIP
Para instalar PIP ejecutamos:
```
sudo yum install python3-pip -y
```
### PostgreSQL
Para instalar postgreSQL ejecutamos:
```
# Install the repository RPM:
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm

# Disable the built-in PostgreSQL module:
sudo dnf -qy module disable postgresql

# Install PostgreSQL:
sudo dnf install -y postgresql14-server

# Optionally initialize the database and enable automatic start:
sudo /usr/pgsql-14/bin/postgresql-14-setup initdb
sudo systemctl enable postgresql-14
sudo systemctl start postgresql-14
```
### IPTables:
Para instalar IPTables ejecutamos:
```
#Paramos el firewalld service
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo systemctl mask --now firewalld

#Instalamos IPTables
sudo yum install iptables-services -y

#Ejecutamos el servicio
sudo systemctl start iptables
sudo systemctl start ip6tables

#Habilitamos sistema
sudo systemctl enable iptables
sudo systemctl enable ip6tables
```
Si queremos asegurarnos que este funcionando ejecutamos:
```
sudo systemctl status iptables
sudo systemctl status ip6tables
```
</details>

<details>
<summary markdown="span">

## Instalacion de librerias Python
</summary>

### Librerias requeridas:
	- psycopg2
	- delegator
	- flask 
	- flask-login
	- flask-sqlalchemy
Comando a ejecutar: ```sudo pip3 install <libreria>```

**En caso de tener problemas instalando psycopg2:**

Si tiene este error: ``` Error: pg_config executable not found ```

Ejecute lo siguiente:
``` sudo yum install postgresql postgresql-devel python-devel ```

Si no se encuentra python-devel, ejecute:
``` yum search python3 | grep devel ```

Seleccione el que quiera instalar segun la version de python y ejecute:
``` sudo yum install -y <paquete_seleccionado> ```

Por ultimo ejecute: ```sudo PATH=$PATH:/usr/pgsql-14/bin/ pip3 install psycopg2```
</details>

<details>
<summary markdown="span">

## Configuracion de Base de Datos 
</summary>

Generamos nueva contraseña para el usuario **postgres**:
Ejecutamos:
```
sudo su postgres
psql
```
``` sql
ALTER USER "postgres" WITH password '<nueva contraseña>';

```
Ahora debemos crear una base de datos llamada **"hips"** y conectarnos a ella. Ejecutamos:
```sql
CREATE DATABASE hips;
\c hips
```
#### Configuracion de pg_hba.conf:
Para que la base de datos pueda funcionar correctamente debemos cambiar el metodo de autentificacion a MD5. Si se encuentra conectado a la base de datos. Ejecutamos:
```
\q 
vim /var/lib/pgsql/14/data/pg_hba.conf
```
Cambiamos:
``` diff
+ local all all peer -> local all all md5
```
Volvemos a root y reiniciamos el servidos de PostgreSQL: 
``` sudo systemctl restart postgres-14.service ```

##Servicio httpd:
Para instalarlo, en caso de no tenerlo. Nos dirijimos al usuario root y ejecutamos:
```
sudo yum install httpd
sudo systemctl start htttpd
sudo systemctl start ssh
```
</details>
<details>
<summary markdown="span">

## Pasos finales
</summary>

Antes que nada, para poblar la base de datos y crear los directorios con los archivos .log debemos ejecutar desde root:
```python
python3 configuracion.py
```
</details>
<details>
<summary markdown="span">

## Conexion al sistema
</summary>

</details>
