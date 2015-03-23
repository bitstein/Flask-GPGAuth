Flask-GPGAuth
================

This is a simple Flask application that uses GPG authentication for registering users and establishing sessions with Flask-Login.

## Setup

Install GPG on your system: https://www.gnupg.org/download/index.html

~~~
mkdir gpgauth-container && cd gpgauth-container
virtualenv venv --no-site-packages
source venv/bin/activate
git clone https://github.com/bitstein/Flask-GPGAuth.git
cd Flask-GPGAuth
pip install -r requirements.txt
python db_create.py
python run.py
~~~

Based on: https://github.com/mrjoes/flask-admin/tree/master/examples/auth and Nanotube's GPG Gribble plugin: https://github.com/nanotube/supybot-bitcoin-marketmonitor/tree/master/GPG

### Notes

This app helps the server verify its users, not the other way around.

This app has not yet been thoroughly tested. Do not use it in production.
