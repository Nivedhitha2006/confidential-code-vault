from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'vault_secret_key'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '123456'
app.config['MYSQL_DB'] = 'codevault'

mysql = MySQL(app)

fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                    (username, email, password))
        mysql.connection.commit()
        flash('Registered successfully!', 'success')
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            return redirect('/vault')
        else:
            flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/vault', methods=['GET', 'POST'])
def vault():
    if 'user_id' not in session:
        return redirect('/login')
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        title = request.form['title']
        language = request.form['language']
        code = request.form['code']
        encrypted_code = cipher.encrypt(code.encode())
        cur.execute("INSERT INTO snippets (user_id, title, language, encrypted_code) VALUES (%s, %s, %s, %s)",
                    (session['user_id'], title, language, encrypted_code))
        mysql.connection.commit()
    cur.execute("SELECT id, title, language, encrypted_code FROM snippets WHERE user_id=%s", (session['user_id'],))
    snippets = cur.fetchall()
    decrypted = [(s[0], s[1], s[2], cipher.decrypt(s[3]).decode()) for s in snippets]
    return render_template('vault.html', codes=decrypted)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
