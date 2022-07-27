#!/usr/bin/python
import datetime
import smtplib
import subprocess
from configparser import ConfigParser 
import psycopg2
import os


#Funcion: Conecta la base de datos del HIPS para poder realizar consultas varias
#Param: Opcion que deseamos consultar
def conexion_bd(op):
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
    
    cursor = conexion.cursor()
        
    #Queries segun opcion como parametro
    #1 Query para mostrar Archivos 
    if op==1: 
        query= '''SELECT (num_hash) FROM md5sum;'''
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            return result
        #Para manejar algun error al hacer la consulta
        except psycopg2.Error:
            print("ERROR.")
    #2 Query para mostrar Logins
    elif op==2:
        query= '''SELECT * FROM login''';
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            return result
        except psycopg2.Error:
            print("ERROR.")
    #3 Query para mostrar Sniffers
    elif op==3:
        query= '''SELECT * FROM sniffer''';
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            return result
        except psycopg2.Error:
            print("ERROR.")

    #Cerramos conexion con la base de datos 
    conexion.close()
 
        
#Funcion: Verificar archivos binarios de sistema y en particular modificaciones realizadas
#         en el archivo /etc/passwd o /etc/shadow. Hace uso de la herramienta 
#         md5sum
def verificar_md5sum():
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
    #Consultamos registros existentes en la base de datos 
    consulta= conexion_bd(1)
    #Extraemos los registros que necesitamos 
    cmd5_p = consulta[0]
    cmd5_s = consulta[1]

    #Hacemos la comparacion 
    (aux, mensaje)= comparar_md5(md5_p, cmd5_p, md5_s, cmd5_s)
    if aux== False:
        print("No coinciden")
        alarmas_log("md5sum diferente. Archivos modificados.", '')
        #enviar_email("md5sum diferente. Archivos modificados.")
    return mensaje

#Funcion: para comparar los hash que estan en la BD y los generados por el hips
#Param: hash de la BD y hash del hips
def comparar_md5(md5_p, cmd5_p, md5_s, cmd5_s):
    aux = True
    mensaje = "No hubo cambios en el archivo"
    #/etc/passwd
    temp = cmd5_p[0]
    print(temp)
    print(md5_p)
    if temp != md5_p:
        aux = False
        mensaje= ''
        mensaje= "/etc/passwd fue editado."
    #/etc/shadow
    temp = cmd5_s[0]
    if temp != md5_s:
        aux = False
        mensaje= "/etc/passwd y /etc/shadow fueron editados, no coinciden las md5sum."

    return (aux,mensaje)

#Funcion: Agregar en el directorio /var/log/hips/alarmas.log las alertas que son generadas
#Param: tipo de aleta y la ip fuente donde se genero la alarma
def alarmas_log(tipo_alarma, ip_fuente):
    # Dado el caso que no haya un ip, se designa como null 
    if ip_fuente == '':
        ip_fuente = 'NULL'
    #Agregamos la fecha en el formato DD/MM/AAAA
    fecha = datetime.now().strftime("%Y/%m/%d, %H:%M:%S")
    alarma = fecha + "::" + tipo_alarma + "::" + ip_fuente
    #Agregamos la alarma generada 
    a = subprocess.Popen("sudo bash -c 'echo " + alarma + " >> /var/log/hips/alarmas.log'", stdout=subprocess.PIPE, shell=True)
    (out, err) = a.communicate()

if __name__ == '__main__':
    conexion_bd(1)