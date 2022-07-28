#!/usr/bin/python

from asyncio import subprocess
import configparser
import datetime
from datetime import datetime
import random
import string
import delegator
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import errno
import os
import smtplib
import ssl
import subprocess
import smtplib
import time
import psycopg2
import alarmas_log
import configuracion

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
def conexion_bd(op, archivo):
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
        try:
            cursor.execute("SELECT archivo FROM binarios WHERE archivo=%s", (archivo, ))
            result = cursor.fetchall()
            #print(result)
            if result:
                cursor.execute("SELECT firma FROM binarios WHERE archivo=%s", (archivo, ))
                md5_original=cursor.fetchone()[0]
                return md5_original
            else:
                #Archivo no existe en la base de datos, generamos alarma
                alarmas_log.alarmas_logger.warn("Archivo '{0}' no encontrado en la base de datos.".format(archivo))
                enviar_correo('ALARMA/WARNING','ARCHIVOS BINARIOS', 'Archivo no encontrado en la base de datos. Por favor revisar /var/log/hips/alarmas.log para mas informacion')
        #Para manejar algun error al hacer la consulta
        except psycopg2.Error as error:
            print("Error: {}".format(error))
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
    #4 Query para Procesos
    elif op==4:
        try:
            query= '''SELECT nombre_programa FROM lista_blanca''';
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
def verificar_md5sum(dir_binarios):
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
        firma_act= out.decode('utf-8')
        #Separamos la parte que corresponde al hash
        firma_act= firma_act.split(' ')[0]
        consulta= conexion_bd(1, e)
        #Hacemos la comparacion 
        (aux, mensaje)= comparar_md5(consulta, firma_act)
        if aux== False:
            print("No coinciden. Archivo modificado:", e)
            alarmas_log.alarmas_logger.warn("md5sum diferente. Archivos modificado: '{0}'.".format(e))
            enviar_correo('ALARMA/WARNING','ARCHIVOS BINARIOS', 'Archivo modificado. Por favor revisar /var/log/hips/alarmas.log para mas informacion')
            return mensaje
    if aux==True:
        print("Ningun archivo binario fue modificado. ")

#Funcion: para comparar los hash que estan en la BD y los generados por el hips
#Param: hash de la BD y hash del hips
def comparar_md5(consulta, firma_act):
    aux = True
    mensaje = "No hubo cambios en el archivo"
    #Para comparar 
    if consulta != firma_act:
        aux = False
        mensaje= "Hubo modificacion en el archivo"
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
            alarmas_log.alarmas_logger.warn("La cola de correo supera el limite establecido.")

# Funcion para matar un proceso dato su PID
def matar_proceso(pid):
    comando = "sudo kill -9 " + str(pid)
    delegator.run(comando)

# Procedemos a encontrar los procesos que superen el limite establecido de consumo ram y terminarlos
def analizar_proceso():
    #Porcentaje minimo de uso de CPU por un proceso sospechoso
    max_uso = 70
    #Se almacenan en una lista los procesos que cumplen con las especificaciones
    comando = """sudo ps aux | awk '{print $2, $4, $11}' | sort -k2r | awk '{if($2>"""+str(max_uso)+""") print($0)}'"""
    c = delegator.run(comando)
    lista = c.out.split('\n')
    #Consultamos registros existentes en la base de datos 
    consulta = conexion_bd(4)
    print(lista)
    #Se verifica cada proceso por nombre y pid
    for proceso in lista:
        if len(proceso) != 0:
            proceso_nombre = proceso.split()[2].split('/')[-1] 
            proceso_pid = proceso.split()[0]
            blanca = 0
            #Se verifica que si pertenece a la lista blanca
            for proceso_blanca in consulta:
                if(proceso_nombre == proceso_blanca):
                    # Se identifica como un proceso seguro
                    blanca = 1 
                    print("Proceso seguro")
                    break
            # No se considera como un proceso seguro, se toman medidas
            if blanca == 0 : 
                #ALARMA
                str_pid   = str(proceso_pid)
                alarmas_log.alarmas_logger.warn('[ALARMA]: El proceso ' + str_pid +' se identifico como sospechoso por alto consumo.')
                enviar_correo('ALARMA/WARNING','PROCESO SOSPECHOSO', 'El proceso ' + str_pid +' se identifico como sospechoso por alto consumo.')
                #PREVENCION
                #Matamos el proceso
                matar_proceso(proceso_pid)
                alarmas_log.prevencion_logger.warn('[PREVENCION]: Se mato el proceso ' + str_pid +' por alto consumo sospechoso.')
                enviar_correo('PREVENCION','PROCESO SOSPECHOSO MATADO', 'Se mato el proceso ' + str_pid +' por alto consumo sospechoso.')

def contra_random_generador():
    contrasenha_caracteres = string.ascii_letters + string.digits + string.punctuation
    contrasenha = random.sample(contrasenha_caracteres, 8)
    contrasenha = "".join(contrasenha)
    return contrasenha

def verificar_error_autentificacion():

    #Se busca en los registros todos aquellos que tuvieron error de autentificacion
    p = subprocess.Popen("cat /var/log/secure | grep -i \"(smtp:auth)\" | grep -i \"authentication failure\"", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    registro = output.decode("utf-8")
    contador_registro = dict()

    #Se recorre cada linea del registro y se almacena el usuario
    for linea in registro.splitlines():
        usuario = linea.split('=')[-1]

        #Se cuenta la cantidad de intentos fallidos
        if usuario in contador_registro:
            contador_registro[usuario]+=1 
            
            #Si se detectan mas de 10 intentos fallidos, se toma accion
            if contador_registro[usuario] == 10:
                #Se notifica al administrador y se registra en el logger
                alarmas_log.alarmas_logger.warn('[ALARMA]: Multiples intentos fallidos de ingreso del usuario ' + usuario + '.')
                enviar_correo('ALARMA/WARNING','USUARIO SOSPECHOSO', 'Multiples intentos fallidos de ingreso del usuario ' + usuario + '.')                
                #Se cambia la contra por precaucion
                contra_random_nueva = contra_random_generador()
                p = subprocess.Popen("echo \"" + usuario + ":" + contra_random_nueva + "\" | chpasswd 2> /dev/null", stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                alarmas_log.prevencion_logger.warn('[PREVENCION]: Se cambio la contraseña del usuario ' + usuario +' por actividad sospechosa.')
                enviar_correo('PREVENCION','CAMBIO DE CONTRASEÑA', 'Se cambio la contraseña del usuario ' + usuario +' por actividad sospechosa.')               
        else:
            contador_registro[usuario] = 1
    
       
def main():
    #verificar_md5sum(configuracion.dir_binarios)
    #tam_cola_correo()
    #analizar_proceso()
    #verificar_error_autentificacion()

if __name__=='__main__':
        main()
