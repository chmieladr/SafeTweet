from flask import Blueprint
from . import auth, main

auth_bp = Blueprint('auth', __name__)
main_bp = Blueprint('main', __name__)
