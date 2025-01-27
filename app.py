import os
import sqlite3
import uuid

import bcrypt
import pyotp
from bleach import clean as bleach_clean
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from markdown import markdown
from redis import Redis
from werkzeug.utils import secure_filename

from allowed import ALLOWED_TAGS
from utils import User, DATABASE, init_db, totp_uri_to_qr_code, calculate_entropy, allowed_file

# Flask application initialization
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SESSION_COOKIE_SECURE'] = True
load_dotenv()
app.secret_key = os.getenv("SECRET_KEY")

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
rounds = 10  # number of rounds for bcrypt hashing

# Redis client initialization
redis_host = 'localhost'
redis_port = 6379
redis_client = Redis(host=redis_host, port=redis_port)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=f"redis://{redis_host}:{redis_port}"
)


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("SELECT id, username, password, salt, totp_secret FROM users WHERE username = ?", (username,))
    row = sql.fetchone()
    try:
        user = User()
        user.user_id, user.id, user.password, user.salt, user.totp_secret = row
    except TypeError:
        return None

    return user


@login_manager.request_loader
def request_loader(req):
    username = req.form.get('username')
    user = user_loader(username)
    return user


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        email = request.form.get("email")

        if password != confirm_password:
            return "Passwords do not match!", 400

        # entropy = calculate_entropy(password)
        # if entropy < 50:
        #     return "Password is too weak!", 400

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        totp_secret = pyotp.random_base32()

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute("INSERT INTO users (username, password, salt, email, totp_secret) VALUES (?, ?, ?, ?, ?)",
                    (username, hashed_password, salt, email, totp_secret))
        db.commit()
        db.close()

        totp = pyotp.TOTP(totp_secret)
        totp_uri = totp.provisioning_uri(username, issuer_name="SafeTweet")
        qr = totp_uri_to_qr_code(totp_uri)

        return render_template("setup_2fa.html", totp_provisioning_uri=qr)


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = user_loader(username)

        if user is None or not bcrypt.checkpw(password.encode('utf-8'), user.password):
            return "Wrong login or password!", 401

        totp = pyotp.TOTP(user.totp_secret)
        token = request.form.get("token")
        if not totp.verify(token, valid_window=1):
            return "Invalid 2FA token!", 401

        login_user(user)
        return redirect('/hello')


@app.route("/setup_2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if request.method == "POST":
        user = current_user
        totp_secret = pyotp.random_base32()
        user.totp_secret = totp_secret

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (totp_secret, user.user_id))
        db.commit()
        db.close()

        return redirect('/hello')

    user = current_user
    totp = pyotp.TOTP(user.totp_secret)
    totp_provisioning_uri = totp.provisioning_uri(user.id, issuer_name="SafeTweet")
    return render_template("setup_2fa.html", totp_provisioning_uri=totp_provisioning_uri)


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route("/hello", methods=['GET'])
@login_required
def hello():
    username = current_user.id
    print(f"Logged in as: {username}")

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("""
            SELECT posts.title, posts.body, posts.created_at, users.username, posts.image
            FROM posts
            JOIN users ON posts.user_id = users.id
            ORDER BY posts.created_at DESC
        """)
    posts = sql.fetchall()
    db.close()

    return render_template("index.html", username=username, posts=posts)


@app.route("/render", methods=['POST'])
def render():
    title = request.form.get("title")
    md = request.form.get("post")
    rendered = markdown(md)
    sanitized_text = bleach_clean(rendered, tags=ALLOWED_TAGS, strip=True)

    image = request.files.get('image')
    image_filename = None  # will become NULL in the database if no image is uploaded
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        image.save(image_path)
        image_filename = unique_filename

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("INSERT INTO posts (title, body, user_id, image) VALUES (?, ?, ?, ?)",
                (title, sanitized_text, current_user.user_id, image_filename))
    db.commit()
    db.close()

    return redirect('/hello')


@app.errorhandler(401)
def unauthorized_error(_):
    return render_template('unauthorized.html'), 401


if __name__ == "__main__":
    init_db()
    app.run("127.0.0.1", 8443, debug=True, ssl_context=('certs/cert.pem', 'certs/key.pem'))
