#!/usr/bin/python

from asyncio import subprocess
import configparser
import datetime
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
import ssl
import subprocess
import smtplib
import psycopg2
import alarmas_log

#Variables globales (varias)
SERVIDOR = "smtp-mail.outlook.com"
HIPS_CORREO_ADMIN = "ProyectodeHips@outlook.com"
HIPS_CORREO = "ProyectodeHips@outlook.com"
HIPS_CONTRA = "AmparoyAmandaHIPS1."
SSL_context = ssl.create_default_context()
port = 587
msg = MIMEMultipart() 

#Funcion: Conecta la base de datos del HIPS para poder realizar consultas varias
#Param: Opcion que deseamos consultar
def conexion_bd(op):
    #Buscamos credenciales para acceder a base de datos
    #Establecemos ruta del archivo 
    path = '/'.join((os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
    
    config = configparser.ConfigParser()
    config.read(os.path.join(path, 'database.ini'))
    name_db = config['DEFAULT']['DB_NAME']
    usr_db = config['DEFAULT']['DB_USER']
    pass_db = config['DEFAULT']['DB_PASSWORD']
    #Conexion a la base de datos 
    conexion = psycopg2.connect(database = name_db, user = usr_db, password = pass_db)
    
    cursor = conexion.cursor()
    #if conexion:
    #   print("FUCIONAAAAAA")    
    #Queries segun opcion como parametro
    #1 Query para mostrar Archivos 
    if op==1: 
        query= '''SELECT (firma) FROM binarios;'''
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            #print (result)
            return result
        #Para manejar algun error al hacer la consulta
        except psycopg2.Error:
            print("ERROR.")
    #2 Query para mostrar Logins
    elif op==2:
        query= '''SELECT * FROM login''';
        try:
            cursor.execute(query)
            #print("Lo que hay es: ", cursor.rowcount)
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
    md5= subprocess.Popen('sudo md5sum /etc/passwd', stdout=subprocess.PIPE, shell=True)
    (out,err) =md5.communicate()
    #Para que sea legible 
    md5_p= out.decode('utf-8')
    #Separamos la parte que corresponde al hash
    md5_p= md5_p.split(' ')[0]
    #Realizamos mismo procedimiento para el /etc/shadow
    md5= subprocess.Popen('sudo md5sum /etc/shadow', stdout=subprocess.PIPE, shell=True)
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
    if aux==True:
        print("No se han modificado.")
    if aux== False:
        print("No coinciden")
        #Se envia el correo y se registra en el logger
        enviar_correo('ALARMA/WARNING','MD5SUM', 'Md5sum es diferente. Archivos modificados!') 
        alarmas_log.alarmas_logger.warn("Md5sum es diferente. Archivos modificados!")
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

# Funcion que envia un correo al Administrador una vez detectada una alarma (SMTP)
def enviar_correo(log_level,asunto, msje):
    msg['From']= HIPS_CORREO
    msg['To']= HIPS_CORREO_ADMIN
    msg['Subject']= 'Nivel: ' + log_level + ' | '  + 'Asunto: ' + asunto 
    msg.attach(MIMEText(msje, "plain"))
    text = msg.as_string()
    with smtplib.SMTP(SERVIDOR, port) as server:
        server.starttls(context=SSL_context)
        server.login(HIPS_CORREO, HIPS_CONTRA)
        server.sendmail(HIPS_CORREO, HIPS_CORREO_ADMIN, text)
    server.close()

#Funcion que verifica el tam de cola
def tam_cola_correo():
    #Establecemos un limite de correos
    TAM_MAX = 1000
    #Verificamos la cola de correo
    p = subprocess.Popen("sudo sendmail -bp", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    print(output)
    #Si recibe un mensaje de que esta vacio
    if b'queue is empty' in output:
        print("La cola de mail esta vacia")
        # A modo de prueba ya que no tenemos nada en la cola
        enviar_correo('ALARMA/WARNING','CORREO COLA', 'La cola esta vacia') 
        alarmas_log.alarmas_logger.warn("La cola esta vacia")
    else:
        #Si no esta vacio, se verifica que supere el limite 
        mail_list = output.decode("utf-8").splitlines()
        #Si supera el limite, 
        if len(mail_list) > TAM_MAX:
            # Enviar correo a usuario y agregar al logger alarmas
            enviar_correo('ALARMA/WARNING','CORREO COLA', 'La cola de correo supera el limite establecido.')
           

def main():
    verificar_md5sum()
    tam_cola_correo()
    
if __name__=='__main__':
        main()