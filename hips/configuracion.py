import subprocess
import os
import psycopg2
import string
from configparser import ConfigParser


#Lista para almacenar los directorios y archivos binarios
dir_binarios= ['/etc/passwd','/etc/shadow','/bin','/usr/bin','/usr/sbin']

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


# Funcion: Para almacenar los md5sum generados originalmente en la base de datos
# Param: Lista de los archivos binarios 
def insertar_md5sum(dir_binarios):
    #Para interactuar con la base de datos 
    cursor = conexion.cursor()
    #Para crear la tabla requerida: 
    try:
        cursor.execute("DROP TABLE IF EXISTS binarios")
        cursor.execute("CREATE TABLE binarios(archivo VARCHAR, firma VARCHAR)")
        print("Tabla de binarios creada con exito.")
    except:
        print("No se pudo crear la tabla de binarios")
    #Lista para almacenar las firmas creadas por los archivos 
    directorios=[] 
    for rutas in dir_binarios:
        #Si es un directorio
        if os.path.isdir(rutas):
            auxiliar= os.listdir(rutas)
            #Para agregar las rutas de los archivos dentro del directorio binario
            for elemento in auxiliar:
                directorios.append(rutas + '/'+ elemento)
        #Si es un archivo
        else:
            directorios.append(rutas)

    for e in directorios:
        #Formamos el comando para generar las firmas 
        comando = "sudo md5sum "+ str(e)
        salida=subprocess.Popen(comando, stdout=subprocess.PIPE, shell=True)
        (out,err) =salida.communicate()
        #Para que sea legible 
        firma= out.decode('utf-8')
        #Separamos la parte que corresponde al hash
        firma= firma.split(' ')[0]

        #Insercion de firmas en base de datos
        try:
            cursor.execute("INSERT INTO binarios(archivo, firma) VALUES (%s,%s)", (e, firma))
            conexion.commit()
            ban=True
        #Manejo de excepciones
        except psycopg2.Error as error:
            print("Error: {}".format(error))
            ban=False
    if ban:
        print("Se han cargado las firmas de manera exitosa")
    else:
        print("Hubo un error en la carga de firmas")

#Funcion: para insertar los sniffer mas conocidos en la base de datos 
def insertar_sniffer():
    #Para interactuar con la base de datos 
    cursor = conexion.cursor()
    #Para crear la tabla requerida: 
    try:
        cursor.execute("DROP TABLE IF EXISTS sniffer")
        cursor.execute("CREATE TABLE sniffer(id_sniffer SERIAL, nombre_sniffer VARCHAR)")
        print("Tabla de sniffers creada con exito.")
    except:
        print("No se pudo crear la tabla de sniffers.")

    #Cargamos los sniffers mas conocidos 
    path = '/'.join((os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
    lista = open(os.path.join(path, 'lista_sniffers.txt'), 'r')
	
    #Sacamos los nombres de los sniffers
    for fila in lista:
        sniffers = len(fila) - 1
        sniff = fila[:sniffers]

        try:
            print(sniff)
            #Insertamos a la tabla 
            cursor.execute("INSERT INTO sniffer (nombre_sniffer) VALUES (%s)" ,(sniff, ))
        #Manejos de excepciones
        except psycopg2.Error as error:
            print("Error: {}".format(error))
        conexion.commit()
    lista.close()

#Funcion para insertar los programas que forman parte de la lista blanca en la base de datos
def insertar_lista_blanca():
    try:
        cursor = conexion.cursor()
        cursor.execute("DROP TABLE IF EXISTS lista_blanca")
        cursor.execute("CREATE TABLE lista_blanca(id SERIAL, nombre_programa VARCHAR)")
        print("Tabla de lista blanca creada con exito.")
    except:
        print("Error al crear tabla lista blanca")
        return

    path = '/'.join((os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
    lista_blanca = open(os.path.join(path, 'lista_blanca.txt'), 'r')
    for fila in lista_blanca:
        programa = len(fila) - 1
        nombre = fila[:programa]

        try:
            cursor.execute("INSERT INTO lista_blanca (nombre_programa) VALUES (%s)", (nombre, ))
            print(nombre)
            print ("Insercion exitosa")
        except psycopg2.Error as error:
            print("Error: {}".format(error))
        conexion.commit()
    lista_blanca.close()

def insertar_usuarios():
    try:
        #Iteracion por la base de datos
        cursor = conexion.cursor()   				   
        cursor.execute("DROP TABLE IF EXISTS usuario") 	   
        # creamos la tabla usuario 
        cursor.execute("CREATE TABLE usuario(id SERIAL, username VARCHAR, ip VARCHAR)") 
        print("Tabla de usuario creada con exito.")
    except:
        print("No se pudo crear la tabla de usuario")
        return

    path = '/'.join((os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
    archivo=open(os.path.join(path, 'lista_usuario.txt'),'r') #Abre el archivo que contiene la lista de usuarios permitidos	

    lineas = archivo.read().split(os.linesep)

    for aux in lineas:
        if(aux != ''):
            #Colocamos cada campo en un vector
            vector = aux.split(' ') 
            try:
                cursor.execute("INSERT INTO usuario(username, ip) VALUES (%s,%s)",(vector[0],vector[1]) )
                print("Se cargo con exito los usuarios")
            except psycopg2.Error as error:
                print("Error: {}".format(error))
            conexion.commit()
    archivo.close()
    
    
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
    insertar_md5sum(dir_binarios)
    insertar_sniffer()
    insertar_lista_blanca()
    insertar_usuarios()
    if conexion:
        #cerramos la conexion
        conexion.close()

if '__main__' == __name__:
  main()