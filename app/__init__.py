import gnupg
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from config import GNUPGHOME

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
lm = LoginManager()
lm.init_app(app)

gpg = gnupg.GPG(gnupghome=GNUPGHOME)

from app import views, models
