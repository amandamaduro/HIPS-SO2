#!/usr/bin/python
from asyncio import subprocess
import configparser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import subprocess
import smtplib
import os
from dotenv import load_dotenv
from alarmas_log import (alarmas_logger)

# Take environment variables from .env.
load_dotenv()
# Code of your application, which uses environment variables (os.getenv)
BD_CONTRA = os.getenv('BD_CONTRA')
BD_USUARIO = os.getenv('BD_USUARIO')
HIPS_CORREO = os.getenv("HIPS_CORREO")
HIPS_CORREO_CONTRA = os.getenv("HIPS_CORREO_CONTRA")
HIPS_CORREO_ADMIN = os.getenv("HIPS_CORREO_ADMIN")
SMTP = smtplib.SMTP("smtp.gmail.com")
SMTP.starttls()

# Funcion que envia un correo al Administrador una vez detectada una alarma (SMTP)
def enviar_correo(log_level,asunto, mensaje):
    SMTP.login(user = HIPS_CORREO, password = HIPS_CORREO_CONTRA)
    # SMTP.sendmail(from_addr, to_addrs, msg, mail_options=(), rcpt_options=())
    SMTP.sendmail(HIPS_CORREO, HIPS_CORREO_ADMIN, f"MOTIVO:{log_level}\n{asunto}\n\n{mensaje}")
    SMTP.close()

#Funcion que verifica el tam de cola
def tam_cola_correo():
    #Establecemos un limite de correos
    TAM_MAX = 1000
    #Verificamos la cola de correo
    p = subprocess.Popen("mailq", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    print(output)
    #Si recibe un mensaje de que esta vacio
    if "queue is empty" in output:
        print("La cola de mail esta vacia")
        #como prueba
        alarma_log('COLA VACIA.',ip)
    else:
        #Si no esta vacio, se verifica que supere el limite 
        mail_list = output.decode("utf-8").splitlines()
        #Si supera el limite, 
        if len(mail_list) > TAM_MAX:
            # Enviar correo a usuario y agregar al logger alarmas
            enviar_correo('ALARMA/WARNING','CORREO COLA', 'La cola de correo supera el limite establecido.')
            mensaje =' La cola de correo supera el limite establecido. \n'  
            alarmas_logger.warn(mensaje)

def main():
    tam_cola_correo()
    
if __name__=='__main__':
        main()