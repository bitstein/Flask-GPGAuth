from flask import render_template, flash, redirect, session, url_for, request, g
from flask.ext.login import login_user, logout_user, current_user, login_required
from app import app, db, lm
from forms import LoginForm, RegistrationForm
from models import User
from werkzeug.security import generate_password_hash, check_password_hash

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
    if g.user is not None and g.user.is_authenticated():
        return redirect(url_for('index'))
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = form.get_user()
        login_user(user)
        flash('Logged in')
        return redirect(url_for('index'))
    form_heading = "Login"
    return render_template('form.html', form=form, form_heading=form_heading)

@app.route('/register/', methods=('GET', 'POST'))
def register():
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        user = User()

        form.populate_obj(user)
        user.password = generate_password_hash(form.password.data)

        db.session.add(user)
        db.session.commit()

        flash('Registered. You can now sign in.')
        return redirect(url_for('login'))
    form_heading = 'Register'
    return render_template('form.html', form=form, form_heading=form_heading)

@app.route('/logout/')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/members-only/')
@login_required
def members_only():
    return "If you see this, you're a member."