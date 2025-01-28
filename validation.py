import re


def validate_username(username: str) -> str or None:
    if not username:
        return "Username is required."

    if len(username) < 4 or len(username) > 32:
        return "Username must be between 4 and 32 characters long."

    if not re.match(r'^\w+$', username):
        return "Username can only contain alphanumeric characters and underscores."

    return None


def validate_email(email: str) -> str or None:
    if not email:
        return "E-mail is required."

    if not re.match(r'^[\w.-]+@[\w.-]+\.\w+$', email):
        return "Invalid e-mail address."

    return None


def validate_password(password: str, confirm_password: str) -> str or None:
    if not password:
        return "Password is required."

    if len(password) > 128:
        return "Password cannot exceed 128 characters."

    if not (len(password) >= 8 and
            any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for c in password)):
        return ("Password must have at least 8 characters and must contain at least: "
                "one lowercase letter, one uppercase letter, one number and one special character")

    if password != confirm_password:
        return "Passwords do not match!"

    return None


def validate_new_password(password: str, new_password: str, confirm_password: str) -> str or None:
    if not password:
        return "Password is required."

    if not new_password:
        return "New Password is required."

    return validate_password(new_password, confirm_password)


def validate_title(title: str) -> str or None:
    if not title:
        return "Title is required."

    if len(title) > 64:
        return "Titles cannot exceed 64 characters."

    return None


def validate_post(post: str) -> str or None:
    if not post:
        return "Post cannot be empty!"

    if len(post) > 512:
        return "Posts cannot exceed 512 characters."

    return None
