from app import db
from sqlalchemy.orm import validates
from gnupg import GPG
from config import GNUPGBINARY, GNUPGHOME

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    pgpkey = db.relationship("PGPKey", uselist=False, backref="user")

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id)  # python 2
        except NameError:
            return str(self.id)  # python 3

    def __repr__(self):
        return '<User %r>' % (self.username)

class PGPKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String(50), unique=True)
    is_trusted = db.Column(db.Boolean(), default=False)
    user_id = db.Column(Integer, ForeignKey('user.id'))

    @validates('fingerprint')
    def validate_fingerprint(self, key, field):
        gpg = GPG(gpgbinary=GNUPGBINARY, gnupghome=GNUPGHOME)
        key = gpg.recv_keys('pgp.mit.edu', field)
        assert key.results
        return field

    def __init__(self, **kwargs):
        super(PGPKey, self).__init__(**kwargs)

    def __repr__(self):
        return '<PGPKey %r>' % (self.fingerprint)