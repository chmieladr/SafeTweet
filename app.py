import logging
import os
import sqlite3
import uuid

import bcrypt
import pyotp
from bleach import clean as bleach_clean
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from markdown import markdown
from redis import Redis
from werkzeug.utils import secure_filename

from allowed import ALLOWED_TAGS
from forms import LoginForm, RegistrationForm, TweetForm, PasswordChangeForm, PasswordResetRequestForm, \
    PasswordResetForm
from utils import User, DATABASE, init_db, totp_uri_to_qr_code, allowed_file, endpoint_to_form, generate_key_pair
from validation import validate_username, validate_email, validate_password, validate_post, validate_title, \
    validate_new_password

# Flask application initialization
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SERVER_NAME'] = 'localhost:8443'
load_dotenv()
app.secret_key = os.getenv("SECRET_KEY")

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
rounds = 10  # number of rounds for bcrypt hashing

# Redis client initialization
redis_client = Redis(host='redis', port=6379)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='redis://redis:6379/0'
)

# CSRF protection initialization
csrf = CSRFProtect(app)

# Logging configuration
logging.basicConfig(level=logging.INFO)

# Posts list
posts = []


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    try:
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute("SELECT id, username, password, salt, totp_secret FROM users WHERE username = ?",
                    (username,))
        row = sql.fetchone()
        user = User()
        user.user_id, user.id, user.password, user.salt, user.totp_secret = row
    except (TypeError, sqlite3.Error):
        return None

    return user


@login_manager.request_loader
def request_loader(req):
    username = req.form.get('username')
    user = user_loader(username)
    return user


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("1 per 10 seconds", methods=["POST"])
def register():
    form = RegistrationForm()
    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        email = form.email.data

        error_msg = validate_username(username)
        error_msg = validate_email(email) if not error_msg else error_msg
        if error_msg:
            return render_template("register.html", form=form, error=error_msg)

        try:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()

            sql.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if sql.fetchone():
                return render_template("register.html", form=form,
                                       error="This username is already taken!")

            sql.execute("SELECT 1 FROM users WHERE email = ?", (email,))
            if sql.fetchone():
                return render_template("register.html", form=form,
                                       error="There's already an account registered with the provided e-mail!")

            error_msg = validate_password(password, confirm_password)
            if error_msg:
                return render_template("register.html", form=form, error=error_msg)

            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            totp_secret = pyotp.random_base32()
            private_key_pem, public_key_pem = generate_key_pair()

            sql.execute(
                "INSERT INTO users (username, password, salt, email, totp_secret, private_key, public_key)"
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, hashed_password, salt, email, totp_secret, private_key_pem, public_key_pem))
            db.commit()
            db.close()
        except sqlite3.Error:
            return render_template("register.html", form=form, error="Database error!")

        totp = pyotp.TOTP(totp_secret)
        totp_uri = totp.provisioning_uri(username, issuer_name="SafeTweet")
        qr = totp_uri_to_qr_code(totp_uri)

        return render_template("setup_2fa.html", totp_provisioning_uri=qr)

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("1 per 5 seconds", methods=["POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = user_loader(username)

            if user is None or not bcrypt.checkpw(password.encode('utf-8'), user.password):
                return render_template("login.html", form=form, error="Invalid username or password!")

            totp = pyotp.TOTP(user.totp_secret)
            token = form.token.data
            if not totp.verify(token, valid_window=1):
                return render_template("login.html", form=form, error="Invalid 2FA token!")

            login_user(user)
            return redirect(url_for('feed'))

    return render_template("login.html", form=form)


@app.route("/setup_2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if request.method == "POST":
        user = current_user
        totp_secret = pyotp.random_base32()
        user.totp_secret = totp_secret

        try:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            sql.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (totp_secret, user.user_id))
            db.commit()
            db.close()
        except sqlite3.Error:
            return render_template("setup_2fa.html", error="Database error!")

        return redirect(url_for('feed'))

    user = current_user
    totp = pyotp.TOTP(user.totp_secret)
    totp_provisioning_uri = totp.provisioning_uri(user.id, issuer_name="SafeTweet")
    return render_template("setup_2fa.html", totp_provisioning_uri=totp_provisioning_uri)


@app.route("/manage", methods=["GET"])
@login_required
def manage():
    return render_template("manage.html", username=current_user.id)


@app.route("/change_password", methods=["GET", "POST"])
@limiter.limit("1 per 5 seconds", methods=["POST"])
@login_required
def change_password():
    form = PasswordChangeForm()
    if request.method == "POST" and form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data
        token = form.token.data

        if not bcrypt.checkpw(current_password.encode('utf-8'), current_user.password):
            return render_template("change_password.html", form=form,
                                   error="Current password is incorrect!")

        totp = pyotp.TOTP(current_user.totp_secret)
        if not totp.verify(token, valid_window=1):
            return render_template("change_password.html", form=form,
                                   error="Invalid 2FA token!")

        error_msg = validate_new_password(current_password, new_password, confirm_password)
        if error_msg:
            return render_template("change_password.html", form=form, error=error_msg)

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)

        try:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            sql.execute("UPDATE users SET password = ?, salt = ? WHERE id = ?",
                        (hashed_password, salt, current_user.user_id))
            db.commit()
            db.close()
        except sqlite3.Error:
            return render_template("change_password.html", form=form, error="Database error!")

        return redirect("/feed")

    return render_template("change_password.html", form=form)


@app.route("/reset_password_request", methods=["GET", "POST"])
@limiter.limit("1 per 5 seconds", methods=["POST"])
def reset_password_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = sql.fetchone()
        db.close()

        if user:
            user_id = user[0]
            s = URLSafeTimedSerializer(app.secret_key)
            token = s.dumps(user_id, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True, _scheme='https')
            logging.info(f"The following password reset link for account registered on {email} "
                         f"has been sent: {reset_link}")
        else:
            return render_template("reset_password_request.html", form=form,
                                   error="No account is registered with the provided e-mail address!")

        return redirect(url_for('login'))

    return render_template("reset_password_request.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/feed", methods=['GET'])
@login_required
def feed():
    form = TweetForm()
    logging.info(f"Logged in as: {current_user.id}")

    try:
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute("""
                SELECT p.title, p.body, p.created_at, u.username, p.image, p.signature, u.public_key
                FROM posts p
                JOIN users u ON p.user_id = u.id
                ORDER BY p.created_at DESC
            """)
        posts_from_db = sql.fetchall()
        db.close()
    except sqlite3.Error:
        return render_template("feed.html", username=current_user.id, posts=posts, form=form,
                               post_error="Database error!")

    posts.clear()
    for post in posts_from_db:
        title, body, created_at, username, image, signature, public_key_pem = post
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            public_key.verify(
                signature,
                body.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            posts.append((title, body, created_at, username, image, True))
        except (ValueError, TypeError, InvalidSignature):
            posts.append((title, body, created_at, username, image, False))

    return render_template("feed.html", username=current_user.id, posts=posts, form=form)


@app.route("/tweet", methods=['POST'])
@limiter.limit("1 per 15 seconds", methods=["POST"])
@login_required
def tweet():
    form = TweetForm()
    if form.validate_on_submit():
        title = form.title.data
        md = form.post.data

        # Validation of title's and post's length
        error_msg = validate_title(title)
        error_msg = validate_post(md) if not error_msg else error_msg
        if error_msg:
            return render_template("feed.html", username=current_user.id, posts=posts,
                                   form=form, error=error_msg)

        rendered = markdown(md)
        sanitized_text = bleach_clean(rendered, tags=ALLOWED_TAGS, strip=True)

        try:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            sql.execute("SELECT private_key FROM users WHERE id = ?", (current_user.user_id,))
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

            image = form.image.data
            image_filename = None  # will become NULL in the database when no image is uploaded
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                image.save(image_path)
                image_filename = unique_filename

            sql.execute("INSERT INTO posts (title, body, user_id, image, signature) VALUES (?, ?, ?, ?, ?)",
                        (title, sanitized_text, current_user.user_id, image_filename, signature))
            db.commit()
            db.close()
        except sqlite3.Error:
            return render_template("feed.html", username=current_user.id, posts=posts,
                                   form=form, error="Database error!")

    return redirect(url_for('feed'))


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    s = URLSafeTimedSerializer(app.secret_key)
    try:
        user_id = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return redirect(url_for('login'))

    form = PasswordResetForm()
    if form.validate_on_submit():
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data

        error_msg = validate_password(new_password, confirm_password)
        if error_msg:
            return render_template("reset_password.html", form=form, error=error_msg)

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)

        try:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            sql.execute("UPDATE users SET password = ?, salt = ?, totp_secret = ? WHERE id = ?",
                        (hashed_password, salt, pyotp.random_base32(), user_id))
            db.commit()
            sql.execute("SELECT id, username, password, salt, totp_secret FROM users WHERE id = ?",
                        (user_id,))
            row = sql.fetchone()
            db.close()
        except sqlite3.Error:
            return render_template("reset_password.html", form=form, error="Database error!")

        user = User()
        user.user_id, user.id, user.password, user.salt, user.totp_secret = row
        login_user(user)

        totp = pyotp.TOTP(user.totp_secret)
        totp_uri = totp.provisioning_uri(user.id, issuer_name="SafeTweet")
        qr = totp_uri_to_qr_code(totp_uri)

        return render_template("setup_2fa.html", totp_provisioning_uri=qr)

    return render_template("reset_password.html", form=form)


@app.route("/", methods=["GET"])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))  # go to feed if already logged in
    else:
        return redirect(url_for('login'))  # otherwise, go to login page


@app.errorhandler(401)
def unauthorized_error(_):
    return render_template('unauthorized.html'), 401


@app.errorhandler(429)
def ratelimit_handler(_):
    # rendering the same template but with the error message
    # noinspection PyUnresolvedReferences
    return render_template(f"{request.path[1:]}.html",
                           form=endpoint_to_form.get(request.path[1:])(),
                           error="Please wait a moment before trying again."), 429


@app.errorhandler(500)
def internal_error(_):
    return render_template('internal_error.html'), 500


if __name__ == "__main__":
    init_db()
    app.run()
