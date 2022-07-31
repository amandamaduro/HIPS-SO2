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
def conexion_bd(op, arg1):
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
            cursor.execute("SELECT archivo FROM binarios WHERE archivo=%s", (arg1, ))
            result = cursor.fetchall()
            #print(result)
            if result:
                cursor.execute("SELECT firma FROM binarios WHERE archivo=%s", (arg1, ))
                md5_original=cursor.fetchone()[0]
                return md5_original
            else:
                #Archivo no existe en la base de datos, generamos alarma
                alarmas_log.alarmas_logger.warn("Archivo '{0}' no encontrado en la base de datos.".format(arg1))
                enviar_correo('ALARMA/WARNING','ARCHIVOS BINARIOS', 'Archivo no encontrado en la base de datos. Por favor revisar /var/log/hips/alarmas.log para mas informacion')
        #Para manejar algun error al hacer la consulta
        except psycopg2.Error as error:
            print("Error: {}".format(error))
    #2 Query para mostrar Logins
    elif op==2:
        try:
            cursor.execute("SELECT COUNT (*) FROM usuario where username = %s ", (arg1, ))
            result = cursor.fetchone()
            return result
        except psycopg2.Error as error:
            print("Error: {}".format(error))
    #3 Query para mostrar Sniffers
    elif op==3:
        query= '''SELECT nombre_sniffer FROM sniffer''';
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
    consulta = conexion_bd(4, None)
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

def verificar_log_secure():

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
    
#Funcion: Verificar los usuarios que están conectados. Alamcenarlos en una lista
def usuarios_conectados():
    #Para saber que usuarios estan conectados
    comando= "sudo who | awk '{print($1,$5)}' | sort | uniq | sed 's/(//g' | sed 's/)//g' | sed 's/:0//g'"
    c=delegator.run(comando)
    #Separamos por lineas
    lista = c.out.split('\n')
    #Lista para alamacenar usaurios conectados
    lista_usuarios=[]
    for e in lista:
        conectado=e.split()
        #Si es que esta conectado el usuario local
        if len(conectado)==1:
            conectado.append('localhost')
        #Si hay mas conectados 
        if len(conectado)!=0:
            lista_usuarios.append(conectado)
    return lista_usuarios

#Funcion: Saber origen de los usuarios conectados. Si es un usuario desconocido se notifica
def verificar_usuarios():
    #Extraer la lista de usuarios conectados 
    lista= usuarios_conectados()

    #Recorremos cada linea y almacenamos en variables el usuario y direccion
    for linea in lista:
        #Extraemos usuario y direccion de un usuario de la lista
        usuario=linea[0]
        origen=linea[1]
        #Realizamos query para consulta en la tabla de usuarios. Revisamos que el usuario se encuentre en la base de datos 
        consulta=conexion_bd(2, usuario)[0]
        #Si no coincide, es notificado al administrador
        if consulta==0:
            print("No coinciden los datos del usuario. No se encuentra en la base de datos")
            alarmas_log.alarmas_logger.warn("Usuario no esta regisstrado en la base de datos. Posibilidad de intrusion. Datos:"+usuario+'Origen: ['+origen+']')
            enviar_correo('ALARMA/WARNING','USUARIO DESCONOCIDO', 'Conexion de un usuario no registrado. Por favor revisar /var/log/hips/alarmas.log para mas informacion')

def verificar_log_messages():

    #Se busca en los registros todos aquellos que tuvieron error de autentificacion
    p = subprocess.Popen("cat /var/log/messages | grep -i \"[service=smtp]\" | grep -i \"auth failure\"", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    registro = output.decode("utf-8")
    contador_registro = dict()

    #Se recorre cada linea del registro y se almacena el usuario
    for linea in registro.splitlines():
        # Se obtiene el usuario entre corchetes [user=username]
        usuario = [word for word in linea.split() if 'user=' in word][0]
        # Se borran los corchetes
        usuario = usuario[1:]
        usuario = usuario[:-1]
        # Se quita el user=
        usuario = usuario.split('=')[-1]     

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

#Funcion que agrega correo a la lista negra
def bloquear_correo(correo):
    try:
        cmd = f"sudo echo '{correo} REJECT' >> /etc/postfix/sender_access"
        os.system(cmd) 
        os.system("sudo postmap hash:/etc/postfix/sender_access") # creamos la base de datos con el comando postmap
    except Exception:
        print("Error para cargas en la lista negra")

def verificar_log_maillog():

    #Se busca todos los registros de correos enviados
    p = subprocess.Popen("cat /var/log/maillog | grep -i authid", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    registro = output.decode("utf-8")
    contador_registro = dict()

    #Se recorre cada linea del registro y se almacena el correo
    for linea in registro.splitlines():
        # Se obtiene el correo 
        correo = [word for word in linea.split() if 'authid=' in word][0]
        # Se borra la coma final
        correo = correo[:-1]
        # Se quita el authid=
        correo = correo.split('=')[-1]
 
        #Se cuenta la cantidad de correos enviados
        if correo in contador_registro:
            contador_registro[correo]+=1 
            
            #Si se detectan 50 envios, se considera envio masivo
            if contador_registro[correo] == 50:
                #Se notifica al administrador y se registra en el logger
                alarmas_log.alarmas_logger.warn('[ALARMA]: Envio masivo de correos por parte de:  ' + correo + '.')
                enviar_correo('ALARMA/WARNING','CORREO SOSPECHOSO', 'Envio masivo de correos por parte de:  ' + correo + '.')                
                #Se bloquea el correo por precaucion
                bloquear_correo(correo)
                alarmas_log.prevencion_logger.warn('[PREVENCION]: Se bloqueo el correo:  ' + correo +' por envio masivo.')
                enviar_correo('PREVENCION','CORREO BLOQUEADO', 'Se bloqueo el correo:  ' + correo +' por envio masivo.')               
        else:
            contador_registro[correo] = 1 

#Funcion: Deteccion de si la maquina se encuentra en modo promiscuo
#       Analizamos el archivo var/log/messages
def modo_promiscuo():
    comando = subprocess.Popen('ip a show enp0s3 | grep -i promisc', stdout=subprocess.PIPE, shell=True)
    (out, err)= comando.communicate()
    promiscuo = out.decode('utf-8')
    #print (promiscuo)
    #Se detecta dispositivo en modo promiscuo
    if promiscuo != '':
        #Se registra en alarmas.log y se envia un correo notificando modo promiscuo
        print("La maquina se encuentra en modo promiscuo")
        alarmas_log.alarmas_logger.warn('Se ha detectado dispositivo (servidor enp0s3) se encuentra en modo promiscuo')
        enviar_correo('ALARMA/WARNING','DISPOSITIVO MODO PROMISCUO', 'Se ha detectado que el/los dispositivo/s se encuentra en modo promiscuo. Revise /var/log/hips/alarmas.log para mas informacion.')

    #Para saber si hay otro dispositivo en modo promiscuo
    #Revisamos en el directorio /var/log/secure historial de comandos relacionados con el modo promiscuo
    #Hacemos un analisis con ip link set [interface] promisc on/off
    comando1= subprocess.Popen('sudo cat /var/log/messages | grep "entered promisc"', stdout=subprocess.PIPE, shell=True)
    (out, err) = comando1.communicate()
    c1 = out.decode('utf-8')
    comando2= subprocess.Popen('sudo cat /var/log/messages | grep "left promisc"', stdout=subprocess.PIPE, shell=True)
    (out, err) = comando2.communicate()
    c2 = out.decode('utf-8')
    #convertimos en listas
    promiscuo_on = c1.splitlines()
    promiscuo_off = c2.splitlines()
    #print(promiscuo_on)
    #print(promiscuo_off)
    p_on = len(promiscuo_on)
    p_off = len(promiscuo_off)
    if p_on != p_off:
        #Lista para comparar entre on/off
        comp=[]
        #Lista para almacenar dispositivos que estan en modo promiscuo
        disp_on=[]
        for i in promiscuo_off:
            comp.append(i.split()[-4])
        for j in promiscuo_on:
            comp.append(j.split()[-4])

        contador={i:comp.count(i) for i in comp}
        for d in contador:
            #Analizamos si se prendio y no apago
            if contador[d]%2 != 0:
                disp_on.append(d)
        for d in disp_on:
            print(d+ ": En modo promiscuo")
            alarmas_log.alarmas_logger.warn('Se ha detectado dispositivo' +d +'se encuentra en modo promiscuo')
            enviar_correo('ALARMA/WARNING','DISPOSITIVO MODO PROMISCUO', 'Se ha detectado que el/los dispositivo/s se encuentra en modo promiscuo. Revise /var/log/hips/alarmas.log para mas informacion.')

    else:
        mensaje='La maquina no esta en modo promiscuo'
        print(mensaje)
        return mensaje

#Funcion: matar proceso dado el nombre del proceso
def matar_proceso_nombre(nombre):
    comando = "sudo pidof " + nombre
    c = delegator.run(comando)
    pid = c.out
    matar_proceso(pid) 

#Funcion: Mover a cuarentena archivo o proceso
def cuarentena(op, archivo):
    # Quitamos todos los permisos
    if op==1:
        comando = "sudo chmod a-wxr " + str(archivo)
        delegator.run(comando)
    elif op==2:
        os.system('chmod 400 ' + '/tmp/' + str(archivo))
    # Mueve al directorio de cuarentena
    comando = "sudo mv "+str(archivo) +" /tmp/cuarentena"
    delegator.run(comando)

#Funcion: Para deteccion de sniffers. Si alguno se encuentra en ejecucio.
#       Matamos proceso y movemos a cuarentena
#Comparamos con la lista de aplicaciones sniffers conocidas de la base de datos
def si_app_sniffers():
    consulta=conexion_bd(3, None)
    for aplicacion in consulta:	
        if len(aplicacion) != 0 :
		# Buscamos si existe un proceso en ejecucion que sea un sniffer 
            comando = "sudo ls -l /proc/*/exe 2>/dev/null | awk '{print($11)}' | grep " + str(aplicacion[0])
            c = delegator.run(comando)
            procesos = c.out.split()
            for p in procesos:
			    #Registramos en el log de alarma y se notifica por correo al detectar que se ha entrado en modo promiscuo
                print("Proceso: "+ p + " en ejecucion. Sniffer detectado.")
                alarmas_log.alarmas_logger.warn('Proceso en ejecucion: ' + p +'. Sniffer detectado')
                enviar_correo('ALARMA/WARNING','SNIFFER DETECTADO', 'Se ha detectado proceso/s en ejecucion que esta/n capturando paquetes. Revise /var/log/hips/alarmas.log para mas informacion.')
				#Procedemos a matar el proceso          	
                matar_proceso_nombre(p)
                #Movemos a cuarentena
                cuarentena(1, p) 
				#Registramos la eliminacion del proceso en el log de prevencion y se notifica
                alarmas_log.prevencion_logger.warn('[PREVENCION]: Se elimino el proceso:  ' + p +' por captura de paquetes.')
                enviar_correo('PREVENCION','PROCESO ELIMINADO Y ENVIADO A CUARENTENA', 'Proceso:  ' + p +' fue eliminado y enviado a cuarentena por capturar paquetes (Sniffer)') 			   

#Funcion: Detectamos si la maquina entro en modo promiscuo segun los registros de auditoria
def si_promisc_aud():
    comando = "sudo aureport --anomaly --input-logs | grep ANOM_PROMISCUOUS | awk '{print $5}' | grep -v '?' | sort | uniq"
    c = delegator.run(comando)
    lista = c.out.split()
    for l in lista: # Se detecta dispositivo en modo promiscuo y proceso causante
        print("Se ha detectado maquina en modo promiscuo causado por proceso: "+ l )
        alarmas_log.alarmas_logger.warn('Se ha detectado maquina en modo promiscuo causado por proceso: '+ l)
        enviar_correo('ALARMA/WARNING','MODO PROMISCUO DETECTADO', 'Se ha detectado maquina en modo promiscuo causado por proceso. Revise /var/log/hips/alarmas.log para mas informacion.')
        # Se cierra el proceso causante
        matar_proceso_nombre(l)
        # Se mueve a cuarentena proceso causante
        cuarentena(1, l)
        #Registramos la cuarentena en el log de prevencion y enviamos al mail
        alarmas_log.prevencion_logger.warn('[PREVENCION]: Se elimino el proceso:  ' + l +'. Causante de que la maquina se encuentre en modo promiscuo.')
        enviar_correo('PREVENCION','PROCESO ELIMINADO Y EN CUARENTENA (MODO PROMISCUO)', 'Proceso:  ' + l + '. Causante de que la maquina se encuentre en modo promiscuo.')

#Funcion: Chequeo completo de modo promiscuo o sniffers en ejecucion 
def si_sniffers(): 
    #determinamos si el equipo entro en modo promiscuo o hay sniffer en ejecucion
    modo_promiscuo()
    si_app_sniffers()
    si_promisc_aud()

# Se blooquea una IP con iptables
def bloquear_ip(ip):
    os.system(f"sudo iptables -I INPUT -s {ip} -j DROP")
    os.system("sudo service iptables save")

# Funcion que verifica el access log y bloquea ip bajo criterio
def verificar_log_access():
    cmd = "sudo cat /home/amparooliver/Descargas/access_log.log | grep -i 'HTTP' | grep -i '404'"
    registro = os.popen(cmd).read().split('\n')
    registro.pop(-1)
    contador = {}
    for linea in registro:
        ip =  linea.split()[0]
        
        if ip in contador:
            contador[ip] = contador[ip] + 1
            if contador[ip] == 10:
                alarmas_log.alarmas_logger.warn('[ALARMA]: Se han encontrado multiples errores de carga de paginas desde la ip:  ' + ip + '.')
                enviar_correo('ALARMA/WARNING','IP SOSPECHOSA', 'Se han encontrado multiples errores de carga de paginas desde la ip:  ' + ip + '.')                
                bloquear_ip(ip) 
                alarmas_log.prevencion_logger.warn('[PREVENCION]: Se bloqueo la ip: ' + ip +' por multiples errores de carga de paginas.')
                enviar_correo('PREVENCION','IP BLOQUEADA', 'Se bloqueo la ip: ' + ip +' por multiples errores de carga de paginas.')

        else:
            contador[ip] = 1

def verificar_log_tcpdumps():
    registro = os.popen("sudo cat /home/amparooliver/Descargas/tcpdump_dns.log").read().split('\n')
    registro.pop(-1)

    contador = {}

    for linea in registro:
        #Formato
        ip_a = linea.split()[2]
        ip_b = linea.split()[4][:-1] 
        if (ip_a, ip_b) in contador:
            contador[(ip_a, ip_b)] = contador[(ip_a, ip_b)] + 1
            # Si hay 10 registros de ip_a a ip_b
            if contador[(ip_a, ip_b)] == 10:
                #Formato
                ip = ip_a.split('.')[:-1]
                ip = f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}"            
                alarmas_log.alarmas_logger.warn('[ALARMA]: Posible ataque DDOS de ip:  ' + ip_a + 'a ip: '+ ip_b)
                enviar_correo('ALARMA/WARNING','IP SOSPECHOSA', 'Posible ataque DDOS de ip:  ' + ip_a + 'a ip: '+ ip_b)                
                bloquear_ip(ip) 
                alarmas_log.prevencion_logger.warn('[PREVENCION]: Se bloqueo la ip: ' + ip +' por multiples errores de carga de paginas.')
                enviar_correo('PREVENCION','IP BLOQUEADA', 'Se bloqueo la ip: ' + ip +' por multiples errores de carga de paginas.')    
        else:
            contador[(ip_a, ip_b)] = 1

#Funcion: Verificar directorio /tmp; que no hayan procesos con nombres extraños o scripts ubicados en el mismo.
#         Si se dectecta algun se manda a cuarentena 
def verificar_tmp():
    for direccion,_,nombre_arch in os.walk('/tmp'):
        #Si encontramos algun archivo ejecutable dentro del directorio se notifica y se mueve a cuarentena 
        for aux in nombre_arch:
            if (('.py' in aux) or ('.exe' in aux) or ('.sh' in aux) or ('.deb' in aux) or ('.rpm' in aux) or ('.php' in aux) or ('.c' in aux) or ('.cpp' in aux) or ('.perl' in aux) or ('.ruby' in aux)):
                alarmas_log.alarmas_logger.warn('Se ha detectado archivo ejecutable sospechoso: '+ aux)
                enviar_correo('ALARMA/WARNING','EJECUTABLE SOSPECHOSO', 'Se ha detectado archivo ejecutable sospechoso. Revise /var/log/hips/alarmas.log para mas informacion.')
                #Movemos a cuarentena 
                cuarentena(2, aux)
                #Notificamos por correo la accion tomada 
                alarmas_log.prevencion_logger.warn('[PREVENCION]: El archivo ejecutable sospechoso:  ' + aux +' puesto en cuarentena')
                enviar_correo('PREVENCION','ARCHIVO SOSPECHOSO', 'El archivo ejecutable:  ' + aux + ' se encuentra en cuarentena. Archivo sospechoso.')
                #avisamos en la terminal que existe un ejecutable sospechoso en /tmp
                os.system('echo "Ejecutable detectado:' +str(aux)+ ', notificado por correo. Por favor revisar"')
    #Aplicamos el mismo proceso para el directorio /var/tmp
    for direccion,_,nombre_arch in os.walk('/var/tmp'):
        #Si encontramos algun archivo ejecutable dentro del directorio generamos la alarma al administrador 
        #Y colocamos en cuarentena el ejecutable
        for aux in nombre_arch:
            if (('.py' in aux) or ('.exe' in aux) or ('.sh' in aux) or ('.deb' in aux) or ('.rpm' in aux) or ('.php' in aux) or ('.c' in aux) or ('.cpp' in aux) or ('.perl' in aux) or ('.ruby' in aux)):
                alarmas_log.alarmas_logger.warn('Se ha detectado archivo ejecutable sospechoso: '+ aux + ' en /var/tmp')
                enviar_correo('ALARMA/WARNING','EJECUTABLE SOSPECHOSO', 'Se ha detectado archivo ejecutable sospechoso. Revise /var/log/hips/alarmas.log para mas informacion.')
                cuarentena(2, aux)
                #guardamos el log y notificamos
                alarmas_log.prevencion_logger.warn('[PREVENCION]: El archivo ejecutable sospechoso:  ' + aux +' en /var/tmp puesto en cuarentena')
                enviar_correo('PREVENCION','ARCHIVO SOSPECHOSO', 'El archivo ejecutable:  ' + aux + ' se encuentra en cuarentena. Archivo sospechoso.')
                #avisamos en la terminal que existe un ejecutable sospechoso en /tmp
                os.system('echo "Ejecutable detectado: ' +str(aux)+ ' notificado por correo. Por favor revisar"')

#Funcion que verifica si hay tareas ejecutandose como CRON
def verificar_tarea_cron():
    #Se obtiene la informacion de usuarios
    registro = os.popen("sudo cat /etc/passwd").read().split('\n') 
    registro.pop(-1)
    #Se analiza cada linea del registro, sacando solo el usuario
    for linea in registro:
        usuario = linea.split(':')[0] 
        tareas = [] 
        # Se analiza si el usuario tiene tareas que se estan ejecutando como cron
        try:
            tareas = os.popen(f"sudo crontab -l -u {usuario}").read().split('\n')
            tareas.pop(-1)
        except Exception:
            pass
        
        # Si el usuario tiene tareas entonces recorremos cada tarea
        if tareas:
            for linea_tarea in tareas:
                tarea_cron =  linea_tarea.split()[-1] # Obtenemos solo el archivo que se esta ejecutando como cron
                #ALARMA, se le notifica al administrador y se registra en el log
                alarmas_log.alarmas_logger.warn('[ALARMA]: El usuario: ' + usuario + ' esta ejecutando el archivo: '+ tarea_cron + ' como CRON.')
                enviar_correo('ALARMA/WARNING','TAREA COMO CRON', 'El usuario: ' + usuario + ' esta ejecutando el archivo: '+ tarea_cron + ' como CRON.')
                
#Funcion: Verificar intentos de accesos no válidos. Ya sea desde un mismo usuario
#intentos repetitivos o desde un IP intentos de accesos con múltiples usuarios.
def ssh_log_secure():
    #Extraemos las entradas con contrasehnas fallidas
    contra_fallada = os.popen("cat /var/log/secure | grep 'Failed password'").read()
    contra_fallada = contra_fallada.split(os.linesep)
    contador = []
    #Recorremos archivo
    for fila_log in contra_fallada[:-1]:
        #Capturamos la ip si encontramos la frase "for invalid user"
        if 'for invalid user' in fila_log:
            #Para acceder al ip de un usuario no valido
            ip_sin_acceso= fila_log.split(' ')[12]
        else:
            #Para acceder a un ip de un usuario valido
            ip_sin_acceso= fila_log.split(' ')[10]
        #Registramos la fecha 
        fecha = fila_log.split(' ')[0] + fila_log.split(' ')[1]
        contador.append((fecha, ip_sin_acceso))

    #Creamos una tupla de 2 elementos que almacenan la ip y el contador de acceso 
    contador_ip= [[i, contador.count(i)] for i in set(contador)]
    
    for j in contador_ip:
    #Establecimos como limite 5 intentos, por tanto si los supera
        if j[1] > 5: 
            #Notificamos por correo alarma generada
            alarmas_log.prevencion_logger.warn('Ip: ' + j[0][1] + 'supero el maximo de intentos de acceso atraves de ssh. Ip bloqueado')
            enviar_correo('[PREVENCION]','IP ACCESO DENEGADO', 'Ip/usuario supero el limite de intentos de acceso al sistema por SSH. Revise /var/log/hips/prevencion.log para mas informacion.')
            os.system('echo "\nIp supero los intentos de acceso, ip bloqueado. Revise el correo para mas informacion"')
            #Bloqueamos ip
            bloquear_ip(j[0][1])
    #Extraemos las entradas con acceso fallido
    acceso_fallado = os.popen('cat /var/log/secure | grep "FAILED LOGIN"').read()
    acceso_fallado = acceso_fallado.split(os.linesep)
    cont_usuario = []
    #Recorremos archivo
    for fila_log in acceso_fallado[:-1]:
        #Capturamos la ip si encontramos la frase "for invalid user"
        if not 'User not known to the underlying authentication module' in fila_log:
            #Localizamos usuario 
            ip_sin_acceso= fila_log.split(' ')[11]
            #Registramos la fecha 
            fecha = fila_log.split(' ')[0] + fila_log.split(' ')[1]
            contador.append(fecha, ip_sin_acceso)

    #Creamos una tupla de 2 elementos que almacenan la usuario y el contador de acceso 
    usuario_log= [[i, cont_usuario.count(i)] for i in set(contador)]
    for j in usuario_log:
        #Establecimos como limite 5 intentos, por tanto si los supera
        if j[1] > 5: 
            if not 'root' in j[0][1][:-1]:
                #Si no es root cambiamos la contrasehna 
                nueva_contra=contra_random_generador()
                os.system('echo "'+ j[0][1][:-1] + ':'+ nueva_contra + '" | chpasswd')
                alarmas_log.prevencion_logger.warn('Cambio de contrasenha de: ' + j[0][1][:-1] + ' a ' +nueva_contra +'por superar el maximo de intentos de acceso al sistema')
                enviar_correo('[PREVENCION]','CAMBIO DE CONTRASEHNA', 'Cambio de contrasenha de: ' + j[0][1][:-1]+ ' por superar limite de intentos de acceso al sistema' + nueva_contra)
                os.system('echo "\nIp supero los intentos de acceso. Notificacion al correo"')
            else:
                #Si es root generamos alarma
                alarmas_log.alarmas_logger.warn('Usuario root supero limite de intentos de acceso al sistema.' )
                enviar_correo('ALARMA/WARNING','INTENTO DE ACCESO', 'Usuario root supero limite de intentos de acceso al sistema.')
                os.system('echo " Usuario root supero los intentos de acceso. Notificacion al correo"')

def main():
    #verificar_md5sum(configuracion.dir_binarios)
    #tam_cola_correo()
    #analizar_proceso()
    #verificar_log_secure()
    #verificar_log_messages()
    #verificar_log_maillog()
    #verificar_usuarios()
    #si_sniffers()
    #verificar_log_access()
    #verificar_log_tcpdumps()
    #verificar_tmp()
    #verificar_tarea_cron()
    ssh_log_secure()


if __name__=='__main__':
        main()
