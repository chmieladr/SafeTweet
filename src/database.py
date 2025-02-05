import hashlib
import os
import sqlite3
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import current_app
from werkzeug.utils import secure_filename

from .utils import is_image, User


def get_connection():
    return sqlite3.connect(current_app.config['DATABASE_URL'])


def get_user_by_username(username: str) -> User:
    db = get_connection()
    sql = db.cursor()
    sql.execute("SELECT id, username, password, salt, totp_secret FROM users WHERE username = ?",
                (username,))
    row = sql.fetchone()
    user = User()
    user.user_id, user.id, user.password, user.salt, encrypted_totp_secret = row
    user.totp_secret = Fernet(current_app.config['SYMMETRIC_KEY'].encode()).decrypt(encrypted_totp_secret).decode()
    return user


def get_user_by_id(user_id: int) -> User:
    db = get_connection()
    sql = db.cursor()
    sql.execute("SELECT id, username, password, salt, totp_secret FROM users WHERE id = ?",
                (user_id,))
    row = sql.fetchone()
    user = User()
    user.user_id, user.id, user.password, user.salt, encrypted_totp_secret = row
    user.totp_secret = Fernet(current_app.config['SYMMETRIC_KEY'].encode()).decrypt(encrypted_totp_secret).decode()
    return user


def validate_existing_user(username: str, email: str):
    message = None
    db = get_connection()
    sql = db.cursor()

    sql.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if sql.fetchone():
        message = "This username is already taken!"

    sql.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    if sql.fetchone():
        message = "There's already an account registered with the provided e-mail!"

    db.commit()
    db.close()
    return message


def register_user(username: str, hashed_password: bytes, salt: bytes, email: str, totp_secret: str):
    db = get_connection()
    sql = db.cursor()

    totp_secret = Fernet(current_app.config['SYMMETRIC_KEY'].encode()).encrypt(totp_secret.encode())

    sql.execute(
        "INSERT INTO users (username, password, salt, email, totp_secret) VALUES (?, ?, ?, ?, ?)",
        (username, hashed_password, salt, email, totp_secret)
    )
    db.commit()
    db.close()


def update_2fa(user_id: int, totp_secret: str):
    db = get_connection()
    sql = db.cursor()

    totp_secret = Fernet(current_app.config['SYMMETRIC_KEY'].encode()).encrypt(totp_secret.encode())

    sql.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (totp_secret, user_id))
    db.commit()
    db.close()


def update_password(user_id: int, hashed_password: bytes, salt: bytes):
    db = get_connection()
    sql = db.cursor()
    sql.execute("UPDATE users SET password = ?, salt = ? WHERE id = ?", (hashed_password, salt, user_id))
    db.commit()
    db.close()


def insert_public_key(user_id: int, public_key: rsa.RSAPublicKey):
    db = get_connection()
    sql = db.cursor()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sql.execute("INSERT INTO public_keys (user_id, public_key) VALUES (?, ?)", (user_id, public_key_pem))
    db.commit()
    db.close()


def get_user_id_by_email(email: str) -> int or None:
    db = get_connection()
    sql = db.cursor()
    sql.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = sql.fetchone()[0]
    db.close()
    return user


# Main blueprint related functions
def fetch_posts():
    db = get_connection()
    sql = db.cursor()
    sql.execute("""
        SELECT p.title, p.body, p.created_at, u.username, p.image, p.signature, u.id
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    """)
    posts = sql.fetchall()
    db.close()
    return posts


def verify_signature(signature: bytes, user_id: int, title: str, sanitized_text: str) -> bool:
    keys = fetch_public_keys_by_user_id(user_id)
    message = f"{user_id}:{title}:{sanitized_text}".encode()
    message_hash = hashlib.sha256(message).digest()

    for key in keys:
        public_key = serialization.load_pem_public_key(key[0])
        try:
            public_key.verify(
                signature,
                message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except (TypeError, InvalidSignature):
            continue

    return False


def fetch_public_keys_by_user_id(user_id: int):
    db = get_connection()
    sql = db.cursor()
    sql.execute("SELECT public_key FROM public_keys WHERE user_id = ?", (user_id,))
    public_keys = sql.fetchall()
    db.close()
    return public_keys


def insert_post(title: str, sanitized_text: str, user_id: int, form_image):
    db = get_connection()
    sql = db.cursor()

    try:
        with open(current_app.config['KEY_LOCATION'], "r") as f:
            private_key_pem = f.read()
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=current_app.config['KEY_PASSWORD'].encode('utf-8')
            )
        message_hash = hashlib.sha256(f"{user_id}:{title}:{sanitized_text}".encode()).digest()
        signature = private_key.sign(
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except FileNotFoundError:
        signature = None

    image_filename = None  # will become NULL in the database when no image is uploaded
    if form_image and is_image(form_image.filename):
        filename = secure_filename(form_image.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        form_image.save(image_path)
        image_filename = unique_filename

    sql.execute("INSERT INTO posts (title, body, user_id, image, signature) VALUES (?, ?, ?, ?, ?)",
                (title, sanitized_text, user_id, image_filename, signature))
    db.commit()
    db.close()
