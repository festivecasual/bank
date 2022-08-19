import shutil
import os
import sqlite3
import time

from falcon import testing

import bank


class BankTestCase(testing.TestCase):
    def setUp(self):
        super().setUp()

        shutil.copyfile(bank.db_path, bank.db_path + '-original')
        self.app = bank.create_app()

        self.user_token = self.login('seasoned', 'password_s')
        self.throwaway_token = self.login('fresh', 'password_f')
        self.admin_token = self.login('admin', 'password_a')

    def login(self, username, password):
        return self.simulate_post('/session', json={'username': username, 'password': password}).json['token']

    def tearDown(self):
        shutil.copyfile(bank.db_path + '-original', bank.db_path)
        os.unlink(bank.db_path + '-original')


class TestLogin(BankTestCase):
    def test_good(self):
        result = self.simulate_post('/session', json={'username': 'fresh', 'password': 'password_f'})
        self.assertEqual(result.status_code, 200)

    def test_bad_username(self):
        result = self.simulate_post('/session', json={'username': 'user', 'password': 'password_f'})
        self.assertEqual(result.status_code, 401)

    def test_bad_password(self):
        result = self.simulate_post('/session', json={'username': 'admin', 'password': 'password_f'})
        self.assertEqual(result.status_code, 401)
    
    def test_blank_body(self):
        result = self.simulate_post('/session')
        self.assertEqual(result.status_code, 400)


class TestAuthorization(BankTestCase):
    def test_good_user(self):
        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.user_token})
        self.assertEqual(result.status_code, 200)

    def test_good_user_wrong_type(self):
        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.admin_token})
        self.assertEqual(result.status_code, 403)

    def test_bad_token(self):
        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.admin_token[:-4] + 'abcd'})
        self.assertEqual(result.status_code, 401)

    def test_malformed_auth_header(self):
        result = self.simulate_get('/transaction', headers={'Authorization': 'abcdefg'})
        self.assertEqual(result.status_code, 401)

    def test_non_bearer_auth_header(self):
        result = self.simulate_get('/transaction', headers={'Authorization': 'Digest abcdef'})
        self.assertEqual(result.status_code, 401)

    def test_good_token_deleted_user(self):
        con = sqlite3.connect(bank.db_path)
        cur = con.cursor()
        cur.execute("DELETE FROM users WHERE username = 'fresh'")
        con.commit()
        con.close()

        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.throwaway_token})
        self.assertEqual(result.status_code, 401)


class TestLogout(BankTestCase):
    def test_logout(self):
        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.user_token})
        self.assertEqual(result.status_code, 200)

        result = self.simulate_delete('/session', headers={'Authorization': 'Bearer ' + self.user_token})
        self.assertEqual(result.status_code, 200)
        
        time.sleep(2)
        
        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.user_token})
        self.assertEqual(result.status_code, 401)

        self.user_token = self.login('seasoned', 'password_s')

        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.user_token})
        self.assertEqual(result.status_code, 200)


class TestTransaction(BankTestCase):
    def test_valid_trans(self):
        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.user_token})
        self.assertEqual(len(result.json['data']), 3)

    def test_no_trans(self):
        result = self.simulate_get('/transaction', headers={'Authorization': 'Bearer ' + self.throwaway_token})
        self.assertEqual(len(result.json['data']), 0)


class TestBalance(BankTestCase):
    def test_with_trans(self):
        result = self.simulate_get('/balance', headers={'Authorization': 'Bearer ' + self.user_token})
        self.assertEqual(result.json['balance'], 22.08)

    def test_no_trans(self):
        result = self.simulate_get('/balance', headers={'Authorization': 'Bearer ' + self.throwaway_token})
        self.assertEqual(result.json['balance'], 0)
