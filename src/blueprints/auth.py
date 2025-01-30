import logging
import os
import sqlite3

import bcrypt
import pyotp
from cryptography.hazmat.primitives import serialization
from flask import render_template, redirect, url_for, request, Blueprint, current_app
from flask_login import login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

from ..database import get_user_by_username, validate_existing_user, register_user, update_2fa, update_password, \
    get_user_id_by_email, get_user_by_id, insert_public_key
from ..extensions import login_manager, limiter
from ..forms import LoginForm, RegistrationForm, PasswordChangeForm, PasswordResetRequestForm, PasswordResetForm
from ..utils import totp_uri_to_qr_code, generate_key_pair, multiple_hash
from ..validation import validate_username, validate_email, validate_password, validate_new_password

auth_bp = Blueprint('auth', __name__)


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    try:
        return get_user_by_username(username)
    except (TypeError, sqlite3.Error):
        return None


@login_manager.request_loader
def request_loader(req):
    username = req.form.get('username')
    user = user_loader(username)
    return user


@auth_bp.route("/register", methods=["GET", "POST"])
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
            error_msg = validate_existing_user(username, password)
        except sqlite3.Error:
            return render_template("register.html", form=form, error="Database error!")
        if error_msg:
            return render_template("register.html", form=form, error=error_msg)

        error_msg = validate_password(password, confirm_password)
        if error_msg:
            return render_template("register.html", form=form, error=error_msg)

        hashed_password, salt = multiple_hash(password, rounds=current_app.config['BCRYPT_ROUNDS'])
        totp_secret = pyotp.random_base32()

        try:
            register_user(username, hashed_password, salt, email, totp_secret)
        except sqlite3.Error:
            return render_template("register.html", form=form, error="Database error!")

        totp = pyotp.TOTP(totp_secret)
        totp_uri = totp.provisioning_uri(username, issuer_name=current_app.config['APP_NAME'])
        qr = totp_uri_to_qr_code(totp_uri)

        return render_template("setup_2fa.html", totp_provisioning_uri=qr)

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("1 per 5 seconds", methods=["POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        username = form.username.data
        password = form.password.data
        user = user_loader(username)

        if user is None or not bcrypt.checkpw(password.encode('utf-8'), user.password):
            return render_template("login.html", form=form, error="Invalid username or password!")

        totp = pyotp.TOTP(user.totp_secret)
        token = form.token.data
        if not totp.verify(token, valid_window=1):
            return render_template("login.html", form=form, error="Invalid 2FA token!")

        private_key, public_key = generate_key_pair()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                current_app.config['KEY_PASSWORD'].encode('utf-8'))
        )

        try:
            insert_public_key(user.user_id, public_key)
        except sqlite3.Error as e:
            print(e)
            return render_template("login.html", form=form, error="Database error!")

        login_user(user)
        with open(current_app.config['KEY_LOCATION'], "w") as f:
            f.write(current_app.config['KEY_WARNING'] + "\n" + private_key_pem.decode('utf-8'))

        return redirect(url_for('main.feed'))

    return render_template("login.html", form=form)


@auth_bp.route("/setup_2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if request.method == "POST":
        user = current_user
        totp_secret = pyotp.random_base32()
        user.totp_secret = totp_secret

        try:
            update_2fa(user.user_id, totp_secret)
        except sqlite3.Error:
            return render_template("setup_2fa.html", error="Database error!")

        return redirect(url_for('auth.logout'))

    user = current_user
    totp = pyotp.TOTP(user.totp_secret)
    totp_provisioning_uri = totp.provisioning_uri(user.id, issuer_name=current_app.config['APP_NAME'])
    return render_template("setup_2fa.html", totp_provisioning_uri=totp_provisioning_uri)


@auth_bp.route("/manage")
@login_required
def manage():
    return render_template("manage.html", username=current_user.id)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    os.remove(current_app.config['KEY_LOCATION'])
    return redirect(url_for('auth.login'))


@auth_bp.route("/change_password", methods=["GET", "POST"])
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

        hashed_password, salt = multiple_hash(new_password, rounds=current_app.config['BCRYPT_ROUNDS'])

        try:
            update_password(current_user.user_id, hashed_password, salt)
        except sqlite3.Error:
            return render_template("change_password.html", form=form, error="Database error!")

        return redirect(url_for('main.feed'))

    return render_template("change_password.html", form=form)


@auth_bp.route("/reset_password_request", methods=["GET", "POST"])
@limiter.limit("1 per minute", methods=["POST"])
def reset_password_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        user_id = get_user_id_by_email(email)

        if user_id:
            s = URLSafeTimedSerializer(current_app.secret_key)
            token = s.dumps(user_id, salt=current_app.config["PWD_RESET_SALT"])
            reset_link = url_for('auth.reset_password', token=token, _external=True, _scheme='https')
            logging.info(f"The following password reset link for account registered on {email} "
                         f"has been sent: {reset_link}")
        else:
            return render_template("reset_password_request.html", form=form,
                                   error="No account is registered with the provided e-mail address!")

        return redirect(url_for('auth.login'))

    return render_template("reset_password_request.html", form=form)


@auth_bp.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    s = URLSafeTimedSerializer(current_app.secret_key)

    try:
        user_id = s.loads(token, salt=current_app.config["PWD_RESET_SALT"], max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        return redirect(url_for('auth.login'))

    form = PasswordResetForm()
    if form.validate_on_submit():
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data

        error_msg = validate_password(new_password, confirm_password)
        if error_msg:
            return render_template("reset_password.html", form=form, error=error_msg)

        hashed_password, salt = multiple_hash(new_password, rounds=current_app.config['BCRYPT_ROUNDS'])

        try:
            update_password(user_id, hashed_password, salt)
            user = get_user_by_id(user_id)
        except sqlite3.Error:
            return render_template("reset_password.html", form=form, error="Database error!")

        login_user(user)
        totp = pyotp.TOTP(user.totp_secret)
        totp_uri = totp.provisioning_uri(user.id, issuer_name=current_app.config['APP_NAME'])
        qr = totp_uri_to_qr_code(totp_uri)

        return render_template("setup_2fa.html", totp_provisioning_uri=qr)

    return render_template("reset_password.html", form=form)
