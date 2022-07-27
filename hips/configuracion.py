import subprocess
import os
import psycopg2
import string
from configparser import ConfigParser

#Funcion: Generar las firmas de password y de shadow 
def md5_original():
     #Calculamos el hash generado por md5 de /etc/passwd 
    md5= subprocess.Popen('md5sum /etc/passwd', stdout=subprocess.PIPE, shell=True)
    (out,err) =md5.communicate()
    #Para que sea legible 
    md5_p= out.decode('utf-8')
    #Separamos la parte que corresponde al hash
    md5_p= md5_p.split(' ')[0]
    #Realizamos mismo procedimiento para el /etc/shadow
    md5= subprocess.Popen('md5sum /etc/shadow', stdout=subprocess.PIPE, shell=True)
    (out,err) =md5.communicate()
    md5_s= out.decode('utf-8')
    md5_s= md5_s.split(' ')[0]
    #enviamos a la base de datos
    insertar_md5sum(md5_p, md5_s)

# Funcion: Para almacenar los md5sum generados originalmente en la base de datos
# Param: los hash de etc/passwd y etc/shadow 
def insertar_md5sum(password, shadow):
    #Buscamos credenciales para acceder a base de datos
    #Establecemos ruta del archivo 
    path = '/'.join((os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
    
    config = ConfigParser()
    config.read(os.path.join(path, 'database.ini'))
    name_db = config['DEFAULT']['DB_NAME']
    usr_db = config['DEFAULT']['DB_USER']
    pass_db = config['DEFAULT']['DB_PASSWORD']
    #Conexion a la base de datos 
    conexion = psycopg2.connect(database = name_db, user = usr_db, password = pass_db)
    
    #Para interactuar con la base de datos 
    cursor = conexion.cursor()


    #escribimos el query de creacion de BD
    query = "INSERT INTO md5sum (file, num_hash) VALUES ('/etc/passwd','" + password + "'),('/etc/shadow','" + shadow + "');"
    print(query)

    #Manejo de excepciones

    try:
        cursor.execute(query)
        conexion.commit()
        print("Se han cargado las firmas de manera exitosa")
    except psycopg2.Error:
        print("ERROR.")

    #cerramos la conexion
    conexion.close()

#Funcion: Para crear los logs y directorios necesarios
def creacion_log_dir():
    try:
        #Para almacenar alarmas y prevenciones:
        #Para crear directorio correspondiente a hips
        os.system('sudo mkdir /var/log/hips')
        #Para crear archivo alarmas.log 
        os.system('sudo touch /var/log/hips/alarmas.log')
        #Para crear archivo de prevenciones 
        os.system('sudo touch /var/log/hips/prevencion.log')
        #Para crear la carpeta de cuarentena 
        os.system('sudo mkdir /tmp/cuarentena')
        #Cambiamos los permisos para escritura y lectura
        os.system('sudo chmod 644 /tmp/cuarentena')

    except:
        print('Error creando ficheros')

#Main
def main():
    creacion_log_dir()
    md5_original()

if '__main__' == __name__:
  main()