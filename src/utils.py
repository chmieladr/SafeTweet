import logging
import math
import sqlite3
from base64 import b64encode
from io import BytesIO

import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from flask_login import UserMixin
from qrcode.main import QRCode

from .config import Config
from .forms import LoginForm, RegistrationForm, TweetForm, \
    PasswordChangeForm, PasswordResetForm, PasswordResetRequestForm

endpoint_to_form = {
    'reset_password_request': PasswordResetRequestForm,
    'reset_password': PasswordResetForm,
    'login': LoginForm,
    'register': RegistrationForm,
    'tweet': TweetForm,
    'change_password': PasswordChangeForm,
}


class User(UserMixin):
    def __init__(self):
        self.id = None
        self.user_id = None
        self.password = None
        self.salt = None
        self.totp_secret = None


def calculate_entropy(password) -> float:
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in '!@#$%^&*()-_=+[]{}|;:,.<>?/~`' for c in password):
        charset_size += 32
    entropy = len(password) * math.log2(charset_size)
    return entropy


def generate_key_pair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    return private_key, public_key


def init_db():
    logging.info("Initializing database...")
    with open('schema.sql', 'r') as schema:
        script = schema.read()

    database = sqlite3.connect(Config.DATABASE_URL)
    database.cursor().executescript(script)
    database.commit()
    database.close()



def is_image(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def multiple_hash(password: str, rounds: int = 10) -> tuple[bytes, bytes]:
    salt = bcrypt.gensalt(rounds=rounds)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt


def totp_uri_to_qr_code(uri: str) -> str:
    qr = QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='white', back_color='#1e1e1e')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")
