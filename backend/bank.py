import os
from pathlib import Path
import sqlite3
import datetime

import falcon
import jwt
import bcrypt


db_path = Path(os.environ.get('DATABASE_PATH', './bank.db'))
jwt_secret = os.environ.get('JWT_SECRET', 'bank_secret_jwt').encode('utf-8')


def hashpw(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class TokenAuthentication:
    def process_resource(self, req, resp, resource, params):
        req.context.username = None
        req.context.usertype = None

        if not req.auth:
            return

        try:
            auth_method, auth_token = req.auth.split(' ', 1)
        except ValueError:
            raise falcon.HTTPUnauthorized(description='Invalid authentication header')

        if auth_method != "Bearer":
            raise falcon.HTTPUnauthorized(description='Invalid authentication method')

        try:
            token = jwt.decode(auth_token, jwt_secret, algorithms=['HS256'])
            token_username = token['username']
            token_usertype = token['usertype']
        except:
            raise falcon.HTTPUnauthorized(description='Invalid token')

        # Is the user named in the JWT still valid?
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute('''SELECT username FROM users WHERE username = ? AND usertype = ?''', (token_username, token_usertype))
        if not cur.fetchone():
            raise falcon.HTTPUnauthorized(description='Valid token with an invalid user')
        con.close()

        req.context.username = token_username
        req.context.usertype = token_usertype


def require_authentication(req, resp, resource, params, usertype=None):
    if not req.context.username:
        raise falcon.HTTPUnauthorized(description='No authentication credentials provided')
    if usertype and usertype != req.context.usertype:
        raise falcon.HTTPForbidden(description='User not authorized to make this request')


class SessionResource:
    def on_get(self, req, resp):
        login = req.get_media()
        username, password = login.get('username'), login.get('password')

        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute('SELECT password, usertype FROM users WHERE username = ?', (username,))

        row = cur.fetchone()
        if row is None:
            raise falcon.HTTPUnauthorized(description='Invalid user or password')
        else:
            if bcrypt.checkpw(password.encode('utf-8'), row[0]):
                token = jwt.encode({
                    'username': username,
                    'usertype': row[1],
                    'created': datetime.datetime.now().timestamp(),
                }, jwt_secret, algorithm='HS256')
                resp.media = {'token': token}
            else:
                raise falcon.HTTPUnauthorized(description='Invalid user or password')
        
        con.close()


class TransactionResource:
    @falcon.before(require_authentication, 'standard')
    def on_get(self, req, resp):
        print('better have auth!', resp.status)
        print(req.context.username)


app = falcon.App(middleware=[TokenAuthentication()])
app.add_route('/session', SessionResource())
app.add_route('/transaction', TransactionResource(), authenticated=True, usertype='standard')


if __name__ == '__main__':
    import argparse
    import getpass
    import sys
    import os


    parser = argparse.ArgumentParser(description='Manage bank database')
    parser.add_argument('--init', action='store_true', help='Initialize the database')
    parser.add_argument('--add', action='store_true', help='Add a new user')
    parser.add_argument('--admin', action='store_true', help='Make new user an administrator')
    parser.add_argument('--testset', action='store_true', help='Insert test data into the database')
    args = parser.parse_args()

    if args.init:
        db_path.unlink()

    con = sqlite3.connect(db_path)
    cur = con.cursor()

    if args.init:
        cur.execute('''CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, usertype TEXT)''')
        cur.execute('''CREATE TABLE trans (txndate DATE, memo TEXT, username TEXT, amount REAL)''')

    if args.add:
        username = input('Enter username: ')
        password = getpass.getpass('Enter user password: ')
        if password != getpass.getpass('Enter password again: '):
            sys.exit('Typed passwords do not match.')
        usertype = 'admin' if args.admin else 'standard'
        cur.execute('''INSERT INTO users (username, password, usertype) VALUES (?, ?, ?)''', (username, hashpw(password), usertype))

    if args.testset:
        cur.execute('''INSERT INTO users (username, password, usertype) VALUES (?, ?, ?)''', ('user', hashpw('password'), 'standard'))
        cur.execute('''INSERT INTO users (username, password, usertype) VALUES (?, ?, ?)''', ('admin', hashpw('password'), 'admin'))

    con.commit()
    con.close()
