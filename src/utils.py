import math
from base64 import b64encode
from io import BytesIO

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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


def generate_key_pair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
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


def verify_signature(public_key_pem: bytes, signature: bytes, body: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(
            signature,
            body.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False
