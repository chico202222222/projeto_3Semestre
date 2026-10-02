import os
import re
import sqlite3
import base64
import json
from binascii import Error as Base64Error
from contextlib import closing
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (
    Flask, flash, get_flashed_messages, jsonify, redirect, render_template, request,
    send_from_directory, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


ROOT = Path(__file__).resolve().parent.parent
DATABASE = Path(os.environ.get('DATABASE_PATH', Path(__file__).with_name('users.sqlite3')))

app = Flask(__name__, template_folder=ROOT, static_folder=None)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode('ascii')


def connect_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    connection.commit()
    return connection


@app.get('/assets/css/<path:filename>')
@app.get('/css/<path:filename>')
def css_file(filename):
    return send_from_directory(ROOT / 'css', filename)


@app.get('/assets/js/<path:filename>')
@app.get('/js/<path:filename>')
def js_file(filename):
    return send_from_directory(ROOT / 'js', filename)


@app.get('/crypto/public-key')
def get_public_key():
    response = jsonify({'public_key': public_key})
    response.headers['Cache-Control'] = 'no-store'
    return response


def decrypt_form():
    try:
        encrypted_key = base64.b64decode(request.form['encrypted_key'], validate=True)
        iv = base64.b64decode(request.form['iv'], validate=True)
        encrypted_data = base64.b64decode(request.form['encrypted_data'], validate=True)

        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        data = AESGCM(aes_key).decrypt(iv, encrypted_data, None)
        return json.loads(data)
    except (KeyError, ValueError, TypeError, Base64Error, InvalidTag, json.JSONDecodeError):
        return None


@app.get('/')
def home():
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('login'))

    with closing(connect_db()) as connection:
        user = connection.execute(
            'SELECT name FROM users WHERE id = ?', (user_id,)
        ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for('login'))

    return render_template('home.html')


@app.get('/api/user')
def get_user():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'Não autenticado'}), 401

    with closing(connect_db()) as connection:
        user = connection.execute(
            'SELECT name FROM users WHERE id = ?', (user_id,)
        ).fetchone()

    if user is None:
        return jsonify({'error': 'Usuário não encontrado'}), 401

    return jsonify({'name': user['name']})


@app.get('/api/messages')
def get_messages():
    return jsonify(get_flashed_messages())


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if session.get('user_id') is not None:
            return redirect(url_for('home'))
        return render_template('login.html')

    data = decrypt_form()
    if not isinstance(data, dict):
        flash('Não foi possível ler os dados protegidos. Recarregue a página.')
        return redirect(url_for('login'))

    email = data.get('email', '')
    password = data.get('password', '')
    if not isinstance(email, str) or not isinstance(password, str):
        flash('E-mail ou senha incorretos.')
        return redirect(url_for('login'))
    email = email.strip().lower()

    with closing(connect_db()) as connection:
        user = connection.execute(
            'SELECT id, password_hash FROM users WHERE email = ?', (email,)
        ).fetchone()

    if user is None or not check_password_hash(user['password_hash'], password):
        flash('E-mail ou senha incorretos.')
        return redirect(url_for('login'))

    session.clear()
    session['user_id'] = user['id']
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST']) # sem outro metodo liberado
def register():
    if request.method == 'GET':
        return render_template('register.html')

    data = decrypt_form()
    if not isinstance(data, dict):
        flash('Não foi possível ler os dados protegidos. Recarregue a página.')
        return redirect(url_for('register'))

    name = data.get('name', '')
    email = data.get('email', '')
    password = data.get('password', '')
    if not all(isinstance(value, str) for value in (name, email, password)):
        flash('Confira o nome, o e-mail e os requisitos da senha.')
        return redirect(url_for('register'))
    name = name.strip()
    email = email.strip().lower()

    valid_name = 2 <= len(name) <= 100 and re.fullmatch(r'[\w.-]+', name) is not None
    valid_email = len(email) <= 254 and re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email)
    valid_password = (
        8 <= len(password) <= 128
        and re.search(r'[a-z]', password)
        and re.search(r'[A-Z]', password)
        and re.search(r'[0-9]', password)
    )

    if not (valid_name and valid_email and valid_password):
        flash('Confira o nome, o e-mail e os requisitos da senha.')
        return redirect(url_for('register'))

    try:
        with closing(connect_db()) as connection:
            connection.execute(
                'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
                (name, email, generate_password_hash(password)),
            )
            connection.commit()
    except sqlite3.IntegrityError:
        flash('Já existe uma conta com este e-mail.')
        return redirect(url_for('register'))

    flash('Conta criada. Entre com seu e-mail e senha.')
    return redirect(url_for('login'))


@app.post('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
