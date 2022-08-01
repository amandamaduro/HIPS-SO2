from email import message
from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for
)
import flask
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy, _SQLAlchemyState
import psycopg2
import os
import subprocess
import configparser
import hips
import configuracion

class User:
    def __init__(self, id, username, ip, password):
        self.id = id
        self.username = username
        self.ip=ip
        self.password = password

    def __repr__(self):
        return f'<User: {self.username}>'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'prueba'

consult = hips.conexion_bd(5, None)
users = []
print(consult)
for x in range(0,len(consult)):
    users.append(User(consult[x][0],consult[x][1],consult[x][2], consult[x][3]))
print(users)

@app.before_request
def before_request():
    g.user = None

    if 'user_id' in session:
        user = [x for x in users if x.id == session['user_id']][0]
        g.user = user
        print("Entra1")
        print(user)

@app.route('/', methods=['GET', 'POST'])
def login():
    print("entra aca")
    if request.method == 'POST':
        session.pop('user_id', None)
        print("emtra")
        username = request.form['username']
        password = request.form['password']
        print(password)
        print(username)
        if username == '':
            print("vacio")
            return redirect(url_for('login'))
        try:
            user = [x for x in users if x.username == username][0]
            print(user.password)
            if user and user.password == password:
                session['user_id'] = user.id
                return redirect(url_for('index'))
        except:
            redirect(url_for('login'))

    return render_template('login.html')

# Para cargar mi plantilla html
@app.route('/inicio')
def index():
    return render_template('index.html')

@app.route('/usuarios_conectados/')
def usuarios_conectados():
    respuesta = hips.usuarios_conectados()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/verificar_md5sum/')
def verificar_md5sum():
    respuesta = hips.verificar_md5sum(configuracion.dir_binarios)
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/modo_promiscuo/')
def modo_promiscuo():
    respuesta = hips.modo_promiscuo()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/si_app_sniffers/')
def si_app_sniffers():
    respuesta = hips.si_app_sniffers()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/verificar_log_secure/')
def verificar_log_secure():
    respuesta = hips.verificar_log_secure()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/verificar_log_messages/')
def verificar_log_messages():
    respuesta = hips.verificar_log_messages()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/verificar_log_maillog/')
def verificar_log_maillog():
    respuesta = hips.verificar_log_maillog()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/tam_cola_correo/')
def tam_cola_correo():
    respuesta = hips.tam_cola_correo()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/analizar_proceso/')
def analizar_proceso():
    respuesta = hips.analizar_proceso()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/verificar_tmp/')
def verificar_tmp():
    respuesta = hips.verificar_tmp()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/verificar_tarea_cron/')
def verificar_tarea_cron():
    respuesta = hips.verificar_tarea_cron()
    print(respuesta)
    return render_template('index.html', message = respuesta)

@app.route('/ssh_log_secure/')
def ssh_log_secure():
    respuesta = hips.ssh_log_secure()
    print(respuesta)
    return render_template('index.html', message = respuesta)

if __name__ == '__main__':
    app.run(debug=True)