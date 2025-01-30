import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    # Application name
    APP_NAME = 'SafeTweet'
    SERVER_NAME = 'localhost:8443'

    # Secret key for signing cookies
    SECRET_KEY = os.getenv("SECRET_KEY")
    SESSION_COOKIE_SECURE = True

    # Password hashing rounds
    BCRYPT_ROUNDS = 10

    # TOTP symmetric key
    SYMMETRIC_KEY = '46WTbmzSaK2J1XGftp2Po8qnvPWuYte0DKY1uDXQpCQ='

    # Password reset salt
    PWD_RESET_SALT = 'Password-Reset-Salt-1234'

    # Key storage parameters for a private key
    KEY_LOCATION = 'key.pem'
    KEY_PASSWORD = 'Private-Key-Password-9876'
    KEY_WARNING = '--- DO NOT SHARE THIS FILE WITH ANYONE! ---'

    # Folder for storing post images
    UPLOAD_FOLDER = 'static/uploads'

    # Redis and SQLite configuration
    REDIS_URL = 'redis://redis:6379/0'
    DATABASE_URL = './sqlite3.db'

    # Content Security Policy
    CSP = {
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
        'img-src': "'self' data:",
        'connect-src': "'self'",
        'object-src': "'none'",
        'base-uri': "'none'",
        'frame-ancestors': "'none'",
    }

    # Allowed HTML tags for bleach
    ALLOWED_TAGS = [
        'b', 'i', 'u', 'strong', 'em', 'p', 'ul', 'li', 'ol', 'blockquote',
        'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'td', 'hr', 'br'
    ]

    ALLOWED_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif']
