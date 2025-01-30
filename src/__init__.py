import logging
import sqlite3

from flask import Flask
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

from .blueprints import auth_bp, main_bp
from .blueprints.auth import auth_bp
from .blueprints.main import main_bp
from .config import Config
from .error_handlers import register_error_handlers
from .extensions import login_manager, limiter
from .utils import User, endpoint_to_form, init_db


def create_app():
    app = Flask(__name__, static_folder='../static', template_folder='../templates')
    app.config.from_object(Config)  # read config from config.py

    # Setup logging
    logging.basicConfig(level=logging.INFO, format=f"{'-' * 111}\n%(message)s\n{'-' * 111}")

    # Database initialization
    init_db()

    # App initialization
    login_manager.init_app(app)
    limiter.init_app(app)

    # CSRF Protection
    CSRFProtect(app)

    # Content Security Policy
    Talisman(app, content_security_policy=app.config['CSP'], content_security_policy_nonce_in=['script-src'])

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Register Error Handlers
    register_error_handlers(app)

    # Hide Server Header
    @app.after_request
    def remove_server_header(response):
        response.headers.pop('Server', None)
        return response

    # Injection of APP_NAME into templates
    @app.context_processor
    def inject_into_templates():
        return dict(
            APP_NAME=app.config['APP_NAME'],
        )

    return app
