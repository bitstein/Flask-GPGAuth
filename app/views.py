from flask import render_template, flash, redirect, session, url_for, request, g
from flask.ext.login import login_user, logout_user, current_user, login_required
from app import app, db, lm, gpg
from forms import LoginForm, RegistrationForm, ValidationForm
from models import User, PGPKey, PendingAuth, now
import hashlib
import os
from config import GNUPGBINARY, GNUPGHOME
import datetime
from werkzeug.security import generate_password_hash

def clear_expired_auths():
    for auth in PendingAuth.query.filter(PendingAuth.expiry < now() - datetime.timedelta(minutes=10)).all():
        if auth.type == 'register':
            gpg.delete_keys(auth.keyid) 
        db.session.delete(auth)
        db.session.commit()

@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.before_request
def before_request():
    g.user = current_user

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/', methods=('GET', 'POST'))
def login():
    clear_expired_auths()
    if g.user is not None and g.user.is_authenticated():
        return redirect(url_for('index'))
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        chal = hashlib.sha256(os.urandom(128)).hexdigest()[:-8]
        auth = PendingAuth(nick=user.username,
                           keyid=user.pgpkey.keyid,
                           type='login',
                           challenge=generate_password_hash(chal),
                           encrypted=str(gpg.encrypt(chal, user.pgpkey.keyid, always_trust=True)))
        db.session.add(auth)
        db.session.commit()
        return redirect(url_for('validate', keyid=auth.keyid))
    return render_template('login.html', form=form)

@app.route('/register/', methods=('GET', 'POST'))
def register():
    clear_expired_auths()
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        try:
            chal = hashlib.sha256(os.urandom(128)).hexdigest()[:-8]
            auth = PendingAuth(nick=form.username.data,
                               keyid=form.keyid.data,
                               type='register',
                               challenge=generate_password_hash(chal),
                               encrypted=str(gpg.encrypt(chal, form.keyid.data, always_trust=True)))
            db.session.add(auth)
            db.session.commit()
            return redirect(url_for('validate', keyid=auth.keyid))
        except:
            flash('Something is wrong with the fingerprint.')

    return render_template('register.html', form=form)

@app.route('/validate/<keyid>', methods=('GET', 'POST'))
def validate(keyid):
    clear_expired_auths()
    auth = PendingAuth.query.filter_by(keyid=keyid).first()
    form = ValidationForm(request.form, keyid=keyid)
    if auth != None:
        if form.validate_on_submit():
            if auth.type == 'register':
                pgpkey = PGPKey(keyid=auth.keyid)
                db.session.add(pgpkey)
                user = User(username=auth.nick)
                db.session.add(user)
                user.pgpkey = pgpkey
                db.session.commit()
                login_user(user)
                flash('Registered and logged in.')
            if auth.type == 'login':
                user = PGPKey.query.filter_by(keyid=keyid).first().user
                login_user(user)
                flash('Logged in')
            return redirect(url_for('index'))
    return render_template('validate.html', form=form, auth=auth)

@app.route('/logout/')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/members-only/')
@login_required
def members_only():
    return "If you see this, you're a member."