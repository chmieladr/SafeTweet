import math
import sqlite3
from base64 import b64encode
from io import BytesIO

import qrcode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask_login import UserMixin

from allowed import ALLOWED_EXTENSIONS
from forms import PasswordResetRequestForm, LoginForm, RegistrationForm, TweetForm, PasswordChangeForm, \
    PasswordResetForm

DATABASE = "./sqlite3.db"

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


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def init_db():
    print("Initializing database...")
    with open('schema.sql', 'r') as schema:
        script = schema.read()

    database = sqlite3.connect(DATABASE)
    database.cursor().executescript(script)
    database.commit()
    database.close()


def calculate_entropy(password):
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


def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem


def totp_uri_to_qr_code(uri: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='white', back_color='#1e1e1e')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")
