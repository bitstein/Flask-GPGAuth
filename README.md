Flask-Login Demo
================

This is a simple implementation of Flask-Login, including user registration, login, and logout.

## Setup
~~~
mkdir login-container && cd login-container
virtualenv venv --no-site-packages
source venv/bin/activate
git clone https://github.com/bitstein/flask-login-demo.git
cd flask-login-demo
pip install -r requirements.txt
python db_create.py
python run.py
~~~

Based on: https://github.com/mrjoes/flask-admin/tree/master/examples/auth