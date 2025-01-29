from flask import render_template, request
from .utils import endpoint_to_form


def register_error_handlers(app):
    @app.errorhandler(401)
    def unauthorized_error(_):
        return render_template('unauthorized.html'), 401

    @app.errorhandler(404)
    def not_found_error(_):
        return render_template('not_found.html'), 404

    # Rendering the same template but with the error message (when rate limit exceeded)
    @app.errorhandler(429)
    def ratelimit_handler(_):
        # noinspection PyUnresolvedReferences
        return render_template(f"{request.path[1:]}.html",
                               form=endpoint_to_form.get(request.path[1:])(),
                               error="Please wait a moment before trying again."), 429

    @app.errorhandler(500)
    def internal_error(_):
        return render_template('internal_error.html'), 500
