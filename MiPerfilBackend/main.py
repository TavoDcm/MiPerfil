import hashlib
import hmac
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, EmailStr, Field

DB = Path(__file__).with_name('usuarios.db')
app = FastAPI(title='Mi Perfil - API')

class Registro(BaseModel):
    nombre: str = Field(min_length=2, max_length=80)
    correo: EmailStr
    contrasena: str = Field(min_length=8, max_length=100)

class Login(BaseModel):
    correo: EmailStr
    contrasena: str

def conectar():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def iniciar_bd():
    with closing(conectar()) as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            correo TEXT NOT NULL UNIQUE,
            salt TEXT NOT NULL,
            clave_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sesiones (
            token_hash TEXT PRIMARY KEY,
            usuario_id INTEGER NOT NULL,
            expira INTEGER NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        );
        ''')
        con.commit()

def hash_clave(clave, salt):
    return hashlib.pbkdf2_hmac('sha256', clave.encode('utf-8'), bytes.fromhex(salt), 200000).hex()

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()

def obtener_token(authorization):
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(401, 'Debes iniciar sesión')
    return authorization[7:].strip()

iniciar_bd()

@app.get('/')
def inicio():
    return {'mensaje': 'API Mi Perfil funcionando'}

@app.post('/registro', status_code=201)
def registro(datos: Registro):
    salt = secrets.token_hex(16)
    correo = str(datos.correo).strip().lower()
    try:
        with closing(conectar()) as con:
            con.execute('INSERT INTO usuarios(nombre, correo, salt, clave_hash) VALUES (?, ?, ?, ?)',
                        (datos.nombre.strip(), correo, salt, hash_clave(datos.contrasena, salt)))
            con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, 'Este correo ya está registrado')
    return {'mensaje': 'Usuario registrado correctamente'}

@app.post('/login')
def login(datos: Login):
    with closing(conectar()) as con:
        usuario = con.execute('SELECT * FROM usuarios WHERE correo=?', (str(datos.correo).lower(),)).fetchone()
        valido = usuario is not None and hmac.compare_digest(hash_clave(datos.contrasena, usuario['salt']), usuario['clave_hash'])
        if not valido:
            raise HTTPException(401, 'Correo o contraseña incorrectos')
        token = secrets.token_urlsafe(32)
        con.execute('INSERT INTO sesiones(token_hash, usuario_id, expira) VALUES (?, ?, ?)',
                    (hash_token(token), usuario['id'], int(time.time()) + 3600))
        con.commit()
    return {'token': token, 'nombre': usuario['nombre'], 'correo': usuario['correo']}

@app.get('/perfil')
def perfil(authorization: str | None = Header(default=None)):
    token = obtener_token(authorization)
    with closing(conectar()) as con:
        usuario = con.execute('''SELECT u.nombre, u.correo FROM usuarios u
            JOIN sesiones s ON s.usuario_id=u.id WHERE s.token_hash=? AND s.expira>?''',
            (hash_token(token), int(time.time()))).fetchone()
    if usuario is None:
        raise HTTPException(401, 'Sesión vencida o no válida')
    return dict(usuario)

@app.post('/logout')
def logout(authorization: str | None = Header(default=None)):
    token = obtener_token(authorization)
    with closing(conectar()) as con:
        con.execute('DELETE FROM sesiones WHERE token_hash=?', (hash_token(token),))
        con.commit()
    return {'mensaje': 'Sesión cerrada'}
