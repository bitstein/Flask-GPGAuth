from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, validators
from models import User
from werkzeug.security import check_password_hash

class LoginForm(Form):
    username = TextField(validators=[validators.required()])
    password = PasswordField(validators=[validators.required()])

    def validate_username(self, field):
        user = self.get_user()

        if user is None:
            raise validators.ValidationError('Invalid user')

        if not check_password_hash(user.password, self.password.data):
            raise validators.ValidationError('Invalid password')

    def get_user(self):
        return User.query.filter_by(username=self.username.data).first()

class RegistrationForm(Form):
    username = TextField(validators=[validators.required()])
    password = PasswordField(validators=[validators.required()])

    def validate_username(self, field):
        if User.query.filter_by(username=self.username.data).count() > 0:
            raise validators.ValidationError('Duplicate username')