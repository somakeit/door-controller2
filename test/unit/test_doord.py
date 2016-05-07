import unittest
import mock
import sys
import os
import mock
import multiprocessing
import base64

sys.path.append(os.getcwd())
sys.modules['MFRC522'] = __import__('mock_MFRC522')
sys.modules['RPi'] = __import__('mock_RPi')
import doord

class TestTagStatic(unittest.TestCase):

    @mock.patch('doord.Tag.__init__')
    def setUp(self, mock_tag_init):
        mock_tag_init.return_value = None
        self.tag = doord.Tag()

    def test_plus(self):
        assert self.tag.plus(0, 1) == 1
        assert self.tag.plus(1, 1) == 2
        assert self.tag.plus(65534, 1) == 65535
        assert self.tag.plus(65535, 1) == 0
        assert self.tag.plus(32766, 1) == 32767
        assert self.tag.plus(32767, 1) == 32768
        assert self.tag.plus(32768, 1) == 32769
        assert self.tag.plus(1, 2) == 3

    def test_subtract(self):
        assert self.tag.subtract(1, 1) == 0
        assert self.tag.subtract(0, 1) == 65535
        assert self.tag.subtract(65535, 1) == 65534
        assert self.tag.subtract(32768, 1) == 32767
        assert self.tag.subtract(32767, 1) == 32766
    
    def test_greater_than(self):
        assert self.tag.greater_than(1, 0) == True
        assert self.tag.greater_than(0, 1) == False
        assert self.tag.greater_than(0, 56635) == True
        assert self.tag.greater_than(65535, 0) == False
        assert self.tag.greater_than(32767, 0) == True
        assert self.tag.greater_than(32768, 0) == False
        assert self.tag.greater_than(0, 32768) == True
        assert self.tag.greater_than(0, 32767) == False

    def test_less_than(self):
        assert self.tag.less_than(1, 0) == False
        assert self.tag.less_than(0, 1) == True
        assert self.tag.less_than(0, 56635) == False
        assert self.tag.less_than(65535, 0) == True
        assert self.tag.less_than(32767, 0) == False
        assert self.tag.less_than(32768, 0) == True
        assert self.tag.less_than(0, 32768) == False
        assert self.tag.less_than(0, 32767) == True

class TestEntryDatabaseStatic(unittest.TestCase):

    @mock.patch('doord.EntryDatabase.__init__')
    def setUp(self, mock_db_init):
        mock_db_init.return_value = None
        self.db = doord.EntryDatabase()

    def test_vivify(self):
        testdict = {
            'key_a': {
                'key_aa': 1,
                'key_ab': 'must not squash'
            },
            'key_b': 'also must not squash'
        }
        self.db.vivify(testdict, ['key_a','key_aa'], 2)
        self.db.vivify(testdict, ['key_a','key_ac'], 3)
        self.db.vivify(testdict, ['key_c'], 4)
        assert testdict['key_a']['key_aa'] == 2
        assert testdict['key_a']['key_ac'] == 3
        assert testdict['key_c'] == 4
        assert testdict['key_a']['key_ab'] == 'must not squash'
        assert testdict['key_b'] == 'also must not squash'

    def test_server_pull_now(self):
        pass #TODO

class TestEntryDatabase(unittest.TestCase):

    @mock.patch('doord.EntryDatabase.server_pull_now')
    def setUp(self, mock_server_pull_now):
        f = open('doorrc', 'w')
        f.write('{"api_key": "lol", "server_url": "https://example.com"}')
        f.close()

        mock_server_pull_now.return_value = None
        self.db = doord.EntryDatabase()

    def tearDown(self):
        del(self.db)

        try:
            os.remove('doorrc')
        except:
            pass

    def test_tag_user(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_user('fedcba98', '00003')
        assert self.db.get_tag_user('fedcba98') == '00003'
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_count(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_count('fedcba98', 7)
        assert self.db.get_tag_count('fedcba98') == 7
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_a_sector(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_a_sector('fedcba98', 1)
        assert self.db.get_tag_sector_a_sector('fedcba98') == 1
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_b_sector(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_b_sector('fedcba98', 2)
        assert self.db.get_tag_sector_b_sector('fedcba98') == 2
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_a_key_a(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_a_key_a('fedcba98', [1,2,3,4,5,6])
        assert self.db.get_tag_sector_a_key_a('fedcba98') == [1,2,3,4,5,6]
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_a_key_b(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_a_key_b('fedcba98', [1,2,3,4,5,7])
        assert self.db.get_tag_sector_a_key_b('fedcba98') == [1,2,3,4,5,7]
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_b_key_a(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_b_key_a('fedcba98', [1,2,3,4,5,8])
        assert self.db.get_tag_sector_b_key_a('fedcba98') == [1,2,3,4,5,8]
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_b_key_b(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_b_key_b('fedcba98', [1,2,3,4,5,9])
        assert self.db.get_tag_sector_b_key_b('fedcba98') == [1,2,3,4,5,9]
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_a_secret(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_a_secret('fedcba98', "I didn't write these tests until after deploying.")
        assert self.db.get_tag_sector_a_secret('fedcba98') == "I didn't write these tests until after deploying."
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_b_secret(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_b_secret('fedcba98', base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')) #23-bytes of random
        assert self.db.get_tag_sector_b_secret('fedcba98') == base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_get_user_name(self):
        self.db.local.update({'users': {'00003': {'name': 'Eamory'}}})
        assert self.db.get_user_name('00003') == 'Eamory'

    def test_get_user_rules(self):
        self.db.local.update({'users': {'00003': {'roles': [1, 2, 3]}}})
        assert self.db.get_user_roles('00003') == [1, 2, 3]

    def test_log_auth(self):
        self.db.local.update({'tags': {'fedcba98': {'assigned_user': '00001'}}})
        assert len(self.db.unsent.keys()) == 0
        self.db.log_auth('fedcba98', 'DOOR1', 'allowed')
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent['tags']['fedcba98']['scans']) == 1
        assert type(self.db.unsent['tags']['fedcba98']['scans'][0]['date']) == int
        assert self.db.unsent['tags']['fedcba98']['scans'][0]['location'] == 'DOOR1'
        assert self.db.unsent['tags']['fedcba98']['scans'][0]['result'] == 'allowed'
        assert self.db.unsent['tags']['fedcba98']['scans'][0]['assigned_user'] == '00001'

if __name__ == '_main__':
    unittest.main()
