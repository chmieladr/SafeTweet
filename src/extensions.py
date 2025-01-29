# Login Manager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager

from .config import Config

login_manager = LoginManager()

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    storage_uri=Config.REDIS_URL
)
