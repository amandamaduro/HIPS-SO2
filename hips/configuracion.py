'''import subprocess
import os
import psycopg2
import string
import configparser

# Funcion: 
#
# Esta funcion tiene como objetivo almacenar en la base de datos los primeros md5sum generados
#
def send_to_db(pasword, shadow):
    #buscamos las credenciales
    config = configparser.ConfigParser()
    config.read('secret.ini')
    name_db = config['DEFAULT']['DB_NAME']
    usr_db = config['DEFAULT']['DB_USER']
    pass_db = config['DEFAULT']['DB_PASSWORD']
    #establecemos la conexion
    conn = psycopg2.connect(database=name_db, user=usr_db, password=pass_db)

    #creamos el objeto curso para interactuar con la BD
    curr = conn.cursor()

    #escribimos el query de creacion de BD
    sql = "INSERT INTO md5sum (file, num_hash) VALUES ('/etc/passwd','" + tp + "'),('/etc/shadow','" + ts + "');"
    #sql = "select * from md5sum;" 
    print(sql)
    try:
        curr.execute(sql)
        conn.commit()
        print("Carga de datos realizada exitosamente.")
    except psycopg2.Error:
        print("ERROR.")

    #cerramos la conexion
    conn.close()'''