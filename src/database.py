import os
import sqlite3
import uuid

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
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
    user.user_id, user.id, user.password, user.salt, user.totp_secret = row
    return user


def get_user_by_id(user_id: int) -> User:
    db = get_connection()
    sql = db.cursor()
    sql.execute("SELECT id, username, password, salt, totp_secret FROM users WHERE id = ?",
                (user_id,))
    row = sql.fetchone()
    user = User()
    user.user_id, user.id, user.password, user.salt, user.totp_secret = row
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


def register_user(username: str, hashed_password: bytes, salt: bytes, email: str, totp_secret: str,
                  private_key_pem: bytes, public_key_pem: bytes):
    db = get_connection()
    sql = db.cursor()
    sql.execute(
        "INSERT INTO users (username, password, salt, email, totp_secret, private_key, public_key)"
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (username, hashed_password, salt, email, totp_secret, private_key_pem, public_key_pem))
    db.commit()
    db.close()


def update_2fa(user_id: int, totp_secret: str):
    db = get_connection()
    sql = db.cursor()
    sql.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (totp_secret, user_id))
    db.commit()
    db.close()


def update_password(user_id: int, hashed_password: bytes, salt: bytes):
    db = get_connection()
    sql = db.cursor()
    sql.execute("UPDATE users SET password = ?, salt = ? WHERE id = ?", (hashed_password, salt, user_id))
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
        SELECT p.title, p.body, p.created_at, u.username, p.image, p.signature, u.public_key
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    """)
    posts = sql.fetchall()
    db.close()
    return posts


def insert_post(title: str, sanitized_text: str, user_id: int, form_image):
    db = get_connection()
    sql = db.cursor()
    sql.execute("SELECT private_key FROM users WHERE id = ?", (user_id,))
    private_key_pem = sql.fetchone()[0]
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    signature = private_key.sign(
        sanitized_text.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

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
