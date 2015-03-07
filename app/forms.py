from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, HiddenField, validators
from models import User, PGPKey, PendingAuth
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
    keyid = TextField(validators=[validators.required()])

    def validate_username(self, field):
        if User.query.filter_by(username=self.username.data).count() > 0:
            raise validators.ValidationError('Duplicate username')

    def validate_keyid(self, field):
        if PGPKey.query.filter_by(keyid=self.keyid.data).count() > 0:
            raise validators.ValidationError('Duplicate PGP key')

class ValidationForm(Form):
    keyid = HiddenField(validators=[validators.required()])
    challenge = TextField(validators=[validators.required()])

    def validate_challenge(self, field):
        chal = self.get_challenge()
        if chal != self.challenge.data:
            raise validators.ValidationError('Invalid challenge response')

    def get_challenge(self):
        return PendingAuth.query.filter_by(keyid=self.keyid.data).first().challenge