from flask.ext.wtf import Form
from wtforms import TextField, HiddenField, validators
from models import User, PGPKey, PendingAuth
from werkzeug.security import check_password_hash
from app import gpg
from config import KEYSERVERS


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
        if not self.recv_key(self.keyid.data):
            raise validators.ValidationError('Cannot find this PGP key.')

    def recv_key(self, keyid):
        for ks in KEYSERVERS:
            try:
                result = gpg.recv_keys(ks, keyid)
                if 'ok' in result.results[0]:
                    return True
            except:
                continue
        return False


class ValidationForm(Form):
    keyid = HiddenField(validators=[validators.required()])
    challenge = TextField(validators=[validators.required()])

    def validate_challenge(self, field):
        auth = self.get_auth()
        if not check_password_hash(auth.challenge, self.challenge.data):
            raise validators.ValidationError('Invalid challenge response')

    def get_auth(self):
        return PendingAuth.query.filter_by(keyid=self.keyid.data).first()
