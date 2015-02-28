from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, validators
from models import User
from werkzeug.security import check_password_hash

class LoginForm(Form):
    username = TextField(validators=[validators.required()])

    def validate_username(self, field):
        user = self.get_user()

        if user is None:
            raise validators.ValidationError('Invalid user')

    def get_user(self):
        return User.query.filter_by(username=self.username.data).first()

class RegistrationForm(Form):
    username = TextField(validators=[validators.required()])

    def validate_username(self, field):
        if User.query.filter_by(username=self.username.data).count() > 0:
            raise validators.ValidationError('Duplicate username')