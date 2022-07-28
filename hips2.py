#!/usr/bin/python
from asyncio import subprocess
import configparser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import ssl
import subprocess
import smtplib
import os
import sys
#from redmail import outlook
#from dotenv import load_dotenv
import alarmas_log

#Variables globales (varias)
SERVIDOR = "smtp-mail.outlook.com"
HIPS_CORREO_ADMIN = "ProyectodeHips@outlook.com"
HIPS_CORREO = "ProyectodeHips@outlook.com"
HIPS_CONTRA = "AmparoyAmandaHIPS1."
SSL_context = ssl.create_default_context()
port = 587
msg = MIMEMultipart() 

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
        enviar_correo('ALARMA/WARNING','CORREO COLA', 'La cola esta vacia') #para probar
        alarmas_log.alarmas_logger.warn("Hola")
    else:
        #Si no esta vacio, se verifica que supere el limite 
        mail_list = output.decode("utf-8").splitlines()
        #Si supera el limite, 
        if len(mail_list) > TAM_MAX:
            # Enviar correo a usuario y agregar al logger alarmas
            enviar_correo('ALARMA/WARNING','CORREO COLA', 'La cola de correo supera el limite establecido.')
            

def main():
    tam_cola_correo()
    
if __name__=='__main__':
        main()