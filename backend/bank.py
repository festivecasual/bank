import os
import sqlite3
import datetime

import falcon
import jwt
import bcrypt


db_path = os.environ.get('DATABASE_PATH', './bank.db')
jwt_secret = os.environ.get('JWT_SECRET', 'bank_secret_jwt').encode('utf-8')


def hashpw(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def current_timestamp():
    return datetime.datetime.now().timestamp()


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
            token_created = token['created']
        except:
            raise falcon.HTTPUnauthorized(description='Invalid token')

        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute('''SELECT cutoff FROM users WHERE username = ? AND usertype = ?''', (token_username, token_usertype))
        if not (result := cur.fetchone()):
            raise falcon.HTTPUnauthorized(description='Valid token with an invalid user')
        con.close()

        if token_created < result[0]:
            raise falcon.HTTPUnauthorized(description='Token has expired')

        req.context.username = token_username
        req.context.usertype = token_usertype


def require_authentication(req, resp, resource, params, usertype=None):
    if not req.context.username:
        raise falcon.HTTPUnauthorized(description='No authentication credentials provided')
    if usertype and usertype != req.context.usertype:
        raise falcon.HTTPForbidden(description='User not authorized to make this request')


class SessionResource:
    def on_get(self, req, resp):
        username, password = req.params.get('username'), req.params.get('password')

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
                    'created': current_timestamp(),
                }, jwt_secret, algorithm='HS256')
                resp.media = {'token': token}
            else:
                raise falcon.HTTPUnauthorized(description='Invalid user or password')
        
        con.close()

    @falcon.before(require_authentication)
    def on_delete(self, req, resp):
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute('UPDATE users SET cutoff = ? WHERE username = ?', (current_timestamp(), req.context.username))
        con.commit()
        con.close()


class TransactionResource:
    @falcon.before(require_authentication, 'standard')
    def on_get(self, req, resp):
        con = sqlite3.connect(db_path)
        cur = con.cursor()

        con.close()


def create_app():
    app = falcon.App(middleware=[TokenAuthentication()])
    app.add_route('/session', SessionResource())
    app.add_route('/transaction', TransactionResource())
    return app


if __name__ == '__main__':
    import argparse
    import getpass
    import sys

    parser = argparse.ArgumentParser(description='Manage bank database')
    parser.add_argument('--init', action='store_true', help='Initialize the database')
    parser.add_argument('--add', action='store_true', help='Add a new user')
    parser.add_argument('--admin', action='store_true', help='Make new user an administrator')
    parser.add_argument('--stage', action='store_true', help='Insert staging data into the database')
    parser.add_argument('--test', action='store_true', help='Run test suite')
    parser.add_argument('--console', action='store_true', help='Connect to database and launch a SQL REPL')
    args = parser.parse_args()

    if args.test:
        # If we are testing, immediately override the database path to a testing path and force database initialization
        db_path = os.environ['DATABASE_PATH'] = './bank_test.db'
        args.init = args.stage = True

        # Disable user adding and database REPL when testing
        args.add = args.admin = args.console = False

    if args.init and os.path.exists(db_path):
        os.unlink(db_path)

    con = sqlite3.connect(db_path)
    cur = con.cursor()

    if args.init:
        cur.execute('''CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, usertype TEXT, cutoff INTEGER)''')
        cur.execute('''CREATE TABLE trans (txndate DATE, memo TEXT, username TEXT, amount REAL)''')
        con.commit()

    if args.add:
        username = input('Enter username: ')
        password = getpass.getpass('Enter user password: ')
        if password != getpass.getpass('Enter password again: '):
            sys.exit('Typed passwords do not match.')
        usertype = 'admin' if args.admin else 'standard'
        cur.execute('''INSERT INTO users (username, password, usertype, cutoff) VALUES (?, ?, ?, ?)''', (username, hashpw(password), usertype, current_timestamp()))
        con.commit()

    if args.stage:
        cur.execute('''INSERT INTO users (username, password, usertype, cutoff) VALUES (?, ?, ?, ?)''', ('fresh', hashpw('password_f'), 'standard', current_timestamp()))
        cur.execute('''INSERT INTO users (username, password, usertype, cutoff) VALUES (?, ?, ?, ?)''', ('seasoned', hashpw('password_s'), 'standard', current_timestamp()))
        cur.execute('''INSERT INTO users (username, password, usertype, cutoff) VALUES (?, ?, ?, ?)''', ('admin', hashpw('password_a'), 'admin', current_timestamp()))
        con.commit()

        cur.execute('''INSERT INTO trans (txndate, memo, username, amount) VALUES (?, ?, ?, ?)''', (datetime.date.today() - datetime.timedelta(days=30), 'Opening balance', 'seasoned', 21.57))
        cur.execute('''INSERT INTO trans (txndate, memo, username, amount) VALUES (?, ?, ?, ?)''', (datetime.date.today() - datetime.timedelta(days=7), 'Allowance', 'seasoned', 6))
        cur.execute('''INSERT INTO trans (txndate, memo, username, amount) VALUES (?, ?, ?, ?)''', (datetime.date.today(), 'Purchase at Target', 'seasoned', -5.49))
        con.commit()

    if args.console:
        print('Submit a blank line to exit')
        while cmd := input('SQL> '):
            cur.execute(cmd)
            con.commit()
            result = cur.fetchall()
            print(f'[Returned ${len(result)} row(s)]')
            for row in result:
                print('   |',' | '.join([str(v) for v in row]), '| ')

    con.close()

    if args.test:
        import unittest
        unittest.main(module='test', argv=sys.argv[:1])
