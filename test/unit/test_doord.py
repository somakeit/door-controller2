import unittest
import mock
import sys
import os
import mock
import multiprocessing
from multiprocessing import Process
import base64
import requests_mock
import json
import requests.exceptions

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

    def test_encode_bcrypt64(self):
        assert self.tag.encode_bcrypt64('EAFsows8RLtDDZwP3wYfBuUMMeWL6lSp2kswfRuzNSavepq7uAZ.m') == \
            [134, 112, 184, 170, 236, 250, 83, 243, 22, 197, 38, 71, 185, 172, 133, 3, 108, 57, 14, 136,
            53, 252, 73, 173, 184, 233, 202, 225, 4, 215, 15, 197, 197, 224, 202, 246, 176, 176, 1, 40]

    def test_unencode_bcrypt64(self):
        assert self.tag.unencode_bcrypt64([134, 112, 184, 170, 236, 250, 83, 243, 22, 197, 38, 71, 185,
        172, 133, 3, 108, 57, 14, 136, 53, 252, 73, 173, 184, 233, 202, 225, 4, 215, 15, 197, 197, 224,
        202, 246, 176, 176, 1, 40]) == 'EAFsows8RLtDDZwP3wYfBuUMMeWL6lSp2kswfRuzNSavepq7uAZ.m'

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

class TestEntryDatabase(unittest.TestCase):

    @mock.patch('doord.EntryDatabase.server_pull_now')
    def setUp(self, mock_server_pull_now):
        f = open('doorrc', 'w')
        f.write('{"api_key": "lol", "server_url": "https://example.com/rfid"}')
        f.close()

        mock_server_pull_now.return_value = None
        self.db = doord.EntryDatabase()

    def tearDown(self):
        del(self.db)

        try:
            os.remove('doorrc')
        except:
            pass

    @requests_mock.mock()
    def test_server_pull_now(self, internet):
        testdict = {u'some': u'json'}
        assert len(self.db.local.keys()) == 0
        internet.get('https://example.com/rfid', text=json.dumps(testdict))
        self.db.server_pull_now()
        assert internet.request_history[0]._request.headers['Cookie'] == 'SECRET=lol'
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert dict(self.db.local) == testdict

    @mock.patch('requests.get')
    def test_server_pull_now_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException('Like a timeout or something')
        try:
            self.db.server_pull_now()
            assert False
        except doord.EntryDatabaseException:
            pass
    
    @requests_mock.mock()
    def test_server_pull_now_bad_status(self, internet):
        internet.get('https://example.com/rfid', text='Go away', status_code='403')
        try:
            self.db.server_pull_now()
            assert False
        except doord.EntryDatabaseException:
            pass

    @requests_mock.mock()
    def test_server_push_now(self, internet):
        assert len(self.db.send_queue) == 0
        internet.post('https://example.com/rfid', text='OK')
        testdict = {u'some': u'dict'}
        self.db.unsent.update(testdict)
        self.db.server_push_now()
        assert len(internet.request_history) == 1
        assert internet.request_history[0]._request.method == 'POST'
        assert json.loads(internet.request_history[0].text) == testdict
        assert len(self.db.unsent.keys()) == 0
        assert len(self.db.send_queue) == 0
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy

    @requests_mock.mock()
    def test_server_push_now_bad_status(self, internet):
        assert len(self.db.send_queue) == 0
        internet.post('https://example.com/rfid', text='BAD', status_code=400)
        testdict = {u'some': u'dict'}
        self.db.unsent.update(testdict)
        try:
            self.db.server_push_now()
            assert False
        except doord.EntryDatabaseException:
            pass
        assert len(internet.request_history) == 1
        assert internet.request_history[0]._request.method == 'POST'
        assert json.loads(internet.request_history[0].text) == testdict
        assert len(self.db.unsent.keys()) == 0
        assert len(self.db.send_queue) == 1
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy

    @requests_mock.mock()
    def test_server_push_now_retry(self, internet):
        testdict = {u'some': u'dict'}
        self.db.send_queue.append(testdict)
        internet.post('https://example.com/rfid', text='OK')
        self.db.unsent.update(testdict)
        self.db.server_push_now()
        assert len(internet.request_history) == 2
        assert len(self.db.unsent.keys()) == 0
        assert len(self.db.send_queue) == 0
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy    

    @requests_mock.mock()
    def test_server_poll_woker_no_updates(self, internet):
        testdict = {u'some': u'json'}
        assert len(self.db.local.keys()) == 0
        internet.get('https://example.com/rfid', text=json.dumps(testdict))
        self.db._server_poll_worker()
        assert len(internet.request_history) == 1
        assert internet.request_history[0]._request.method == 'GET'
        assert internet.request_history[0]._request.headers['Cookie'] == 'SECRET=lol'
        assert type(self.db.local) == multiprocessing.managers.DictProxy

    @requests_mock.mock()
    def test_server_poll_worker_update(self, internet):
        testdict = {u'some': u'json'}
        testdict2 = {u'some more': u'json'}
        self.db.local.update(testdict)
        self.db.unsent.update(testdict)
        internet.post('https://example.com/rfid', text='OK')
        internet.get('https://example.com/rfid', text=json.dumps(testdict2))
        self.db._server_poll_worker()
        assert len(internet.request_history) == 2
        assert internet.request_history[0]._request.method == 'POST'
        assert json.loads(internet.request_history[0].text) == testdict
        assert internet.request_history[0]._request.headers['Cookie'] == 'SECRET=lol'
        assert internet.request_history[1]._request.method == 'GET'
        assert internet.request_history[1]._request.headers['Cookie'] == 'SECRET=lol'
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        #This also tests a changing db on the server
        assert dict(self.db.local) == testdict2
        
    @requests_mock.mock()
    def test_server_poll_worker_update_retry(self, internet):
        testdict0 = {u'the first': 'json'}
        testdict = {u'some': u'json'}
        testdict2 = {u'some more': u'json'}
        self.db.send_queue.append(testdict0)
        self.db.local.update(testdict)
        self.db.unsent.update(testdict)
        internet.post('https://example.com/rfid', text='OK')
        internet.get('https://example.com/rfid', text=json.dumps(testdict2))
        self.db._server_poll_worker()
        assert len(internet.request_history) == 3
        assert internet.request_history[0]._request.method == 'POST'
        assert json.loads(internet.request_history[0].text) == testdict0
        assert internet.request_history[0]._request.headers['Cookie'] == 'SECRET=lol'
        assert internet.request_history[1]._request.method == 'POST'
        assert json.loads(internet.request_history[1].text) == testdict
        assert internet.request_history[1]._request.headers['Cookie'] == 'SECRET=lol'
        assert internet.request_history[2]._request.method == 'GET'
        assert internet.request_history[2]._request.headers['Cookie'] == 'SECRET=lol'
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        #This also tests a changing db on the server
        assert dict(self.db.local) == testdict2

    @requests_mock.mock()
    def test_server_poll_worker_error_post(self, internet):
        testdict = {u'some': u'json'}
        self.db.unsent.update(testdict)
        internet.post('https://example.com/rfid', text='BAD', status_code=404)
        self.db._server_poll_worker()
        assert len(internet.request_history) == 1
        assert internet.request_history[0]._request.method == 'POST'
        assert json.loads(internet.request_history[0].text) == testdict
        assert internet.request_history[0]._request.headers['Cookie'] == 'SECRET=lol'
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.send_queue) == 1
        assert self.db.send_queue[0] == testdict

    @requests_mock.mock()
    def test_server_poll_worker_error_get(self, internet):
        testdict = {u'some': u'json'}
        testdict2 = {u'some more': u'json'}
        self.db.local.update(testdict)
        self.db.unsent.update(testdict)
        internet.post('https://example.com/rfid', text='OK')
        internet.get('https://example.com/rfid', text='BAD', status_code=500)
        self.db._server_poll_worker()
        assert len(internet.request_history) == 2
        assert internet.request_history[0]._request.method == 'POST'
        assert json.loads(internet.request_history[0].text) == testdict
        assert internet.request_history[0]._request.headers['Cookie'] == 'SECRET=lol'
        assert internet.request_history[1]._request.method == 'GET'
        assert internet.request_history[1]._request.headers['Cookie'] == 'SECRET=lol'
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert dict(self.db.local) == testdict

    @mock.patch('requests.post')
    def test_server_poll_worker_fail_post(self, mock_post):
        testdict = {u'some': u'json'}
        self.db.unsent.update(testdict)
        mock_post.side_effect = requests.exceptions.RequestException('Like maybe cert was expired')
        self.db._server_poll_worker()
        assert mock_post.called
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.send_queue) == 1
        assert self.db.send_queue[0] == testdict

    @requests_mock.mock()
    @mock.patch('requests.get')
    def test_server_poll_worker_fail_get(self, internet, mock_get):
        testdict = {u'some': u'json'}
        testdict2 = {u'some more': u'json'}
        self.db.local.update(testdict)
        self.db.unsent.update(testdict)
        internet.post('https://example.com/rfid', text='OK')
        mock_get.side_effect = requests.exceptions.RequestException('Like the internet is on fire')
        self.db._server_poll_worker()
        assert len(internet.request_history) == 1
        assert internet.request_history[0]._request.method == 'POST'
        assert json.loads(internet.request_history[0].text) == testdict
        assert internet.request_history[0]._request.headers['Cookie'] == 'SECRET=lol'
        assert mock_get.called
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert dict(self.db.local) == testdict

    @mock.patch('multiprocessing.Process.__init__')
    @mock.patch('multiprocessing.Process.start')
    @mock.patch('multiprocessing.Process.is_alive')
    def test_server_poll_launcher_first(self, mock_proc_alive, mock_proc_start, mock_proc_init):
        mock_proc_init.return_value = None
        mock_proc_start.return_value = None
        self.db.server_poll()
        assert mock_proc_start.called

    @mock.patch('multiprocessing.Process.start')
    @mock.patch('multiprocessing.Process.is_alive')
    def test_server_poll_launcher_subsequent(self, mock_proc_alive, mock_proc_start):
        self.db.proc = multiprocessing.Process(target = self.db._server_poll_worker)
        mock_proc_start.return_value = None
        mock_proc_alive.return_value = False
        with mock.patch.object(multiprocessing.Process, '__init__', return_value=None) as mock_proc_init:
            self.db.server_poll()
        assert mock_proc_start.called

    @mock.patch('multiprocessing.Process.start')
    @mock.patch('multiprocessing.Process.is_alive')
    def test_server_poll_launcher_already_running(self, mock_proc_alive, mock_proc_start):
        self.db.proc = multiprocessing.Process(target = self.db._server_poll_worker)
        mock_proc_start.return_value = None
        mock_proc_alive.return_value = True
        with mock.patch.object(Process, '__init__', return_value=None) as mock_proc_init:
            self.db.server_poll()
        mock_proc_start.assert_not_called()

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
