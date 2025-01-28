from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField


class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    token = StringField('2FA Token')
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    username = StringField('Username')
    email = StringField('E-mail')
    password = PasswordField('Password')
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Register')


class TweetForm(FlaskForm):
    title = TextAreaField('Title')
    post = TextAreaField('Post')
    image = FileField('Image')
    submit = SubmitField('Tweet')


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password')
    confirm_password = PasswordField('Confirm New Password')
    token = StringField('2FA Token')
    submit = SubmitField('Change')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('E-mail')
    submit = SubmitField('Request')


class PasswordResetForm(FlaskForm):
    new_password = PasswordField('New Password')
    confirm_password = PasswordField('Confirm New Password')
    submit = SubmitField('Reset')
