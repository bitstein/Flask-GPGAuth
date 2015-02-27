import os
import gnupg
basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

WTF_CSRF_ENABLED = True
SECRET_KEY = 'dont-use-this-secret'

GNUPGBINARY = '/usr/local/bin/gpg'
GNUPGHOME = os.path.abspath(os.path.dirname(__file__)) + '/.gnupg'
TRUST_LEVELS = ('f', 'u') # Trust only f-ully trusted and u-ltimately trusted keys