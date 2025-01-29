import sqlite3

from bleach import clean as bleach_clean
from flask import render_template, redirect, url_for, Blueprint, current_app
from flask_login import login_required, current_user
from markdown import markdown

from ..database import fetch_posts, insert_post
from ..extensions import limiter
from ..forms import TweetForm
from ..utils import verify_signature
from ..validation import validate_title, validate_post

# List for storing loaded posts
posts = []

main_bp = Blueprint('main', __name__)


@main_bp.route("/feed", methods=['GET'])
@login_required
def feed():
    form = TweetForm()

    try:
        posts_from_db = fetch_posts()
    except sqlite3.Error:
        return render_template("feed.html", username=current_user.id, posts=posts, form=form,
                               post_error="Database error!")

    posts.clear()
    for post in posts_from_db:
        title, body, created_at, username, image, signature, public_key_pem = post
        posts.append((title, body, created_at, username, image, verify_signature(public_key_pem, signature, body)))

    return render_template("feed.html", username=current_user.id, posts=posts, form=form)


@main_bp.route("/tweet", methods=['POST'])
@limiter.limit("1 per 15 seconds", methods=["POST"])
@login_required
def tweet():
    form = TweetForm()
    title = form.title.data
    md = form.post.data
    image = form.image.data

    # Validation of title's and post's length
    error_msg = validate_title(title)
    error_msg = validate_post(md) if not error_msg else error_msg
    if error_msg:
        return render_template("feed.html", username=current_user.id, posts=posts,
                               form=form, error=error_msg)

    rendered = markdown(md)
    sanitized_text = bleach_clean(rendered, tags=current_app.config["ALLOWED_TAGS"], strip=True)

    try:
        insert_post(title, sanitized_text, current_user.user_id, image)
    except sqlite3.Error:
        return render_template("feed.html", username=current_user.id, posts=posts,
                               form=form, error="Database error!")

    return redirect(url_for('main.feed'))


@main_bp.route("/", methods=["GET"])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.feed'))  # go to feed if already logged in
    else:
        return redirect(url_for('auth.login'))  # otherwise, go to login page
