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
import crc16
import pep8

sys.path.append(os.getcwd())
sys.modules['MFRC522'] = __import__('mock_MFRC522')
sys.modules['RPi'] = __import__('mock_RPi')
import doord
import MFRC522
import RPi.GPIO


class TestDoorService(unittest.TestCase):

    @requests_mock.mock()
    def setUp(self, internet):
        reload(RPi.GPIO)
        internet.get("https://example.com/rfid", text='{}')
        f = open('doorrc', 'w')
        # Minimum viable doorrc file, fill in extras in methods
        f.write('''
            {
                "api_key": "lol",
                "server_url": "https://example.com/rfid",
                "init_tag_id": "",
                "pull_db_tag_id": "",
                "member_role_id": 4,
                "keyholder_role_id": 5,
                "location_name": ""
            }
            ''')
        f.close()
        self.ds = doord.DoorService()

    def tearDown(self):
        del(self.ds)

    @mock.patch('doord.Tag.__init__')
    def test_iter_no_tag(self, mock_tag_init):
        RPi.GPIO.call_history = []
        self.ds.nfc.return_code = self.ds.nfc.MI_NOTAGERR
        self.ds._iter()
        assert len(RPi.GPIO.call_history) == 0
        mock_tag_init.assert_not_called()

    @mock.patch('doord.Tag.__init__')
    def test_iter_incompat_tag(self, mock_tag_init):
        RPi.GPIO.call_history = []
        self.ds.nfc.return_code = [self.ds.nfc.MI_OK, self.ds.nfc.MI_ERR]
        self.ds._iter()
        assert len(RPi.GPIO.call_history) == 0
        mock_tag_init.assert_not_called()

    @mock.patch('doord.Tag.authenticate')
    def test_iter_recent_tag(self, mock_tag_auth):
        RPi.GPIO.call_history = []
        self.ds.recent_tags = {'fedcba98': os.times()[4] - 1}
        self.ds._iter()
        assert len(RPi.GPIO.call_history) == 0
        mock_tag_auth.assert_not_called()

    @mock.patch('doord.Tag.authenticate')
    def test_iter_tag_not_auth(self, mock_tag_auth):
        RPi.GPIO.call_history = []
        self.ds.recent_tags = {'fedcba98': os.times()[4] - 10}  # also tests nonrecentness
        mock_tag_auth.return_value = (False, [5])  # keyholder but auth failed, shouldn't actually happen
        self.ds._iter()
        # the door was not opened
        for call in RPi.GPIO.call_history:
            assert call['pin'] != self.ds.DOOR_IO
        assert mock_tag_auth.call_count == 1

    @mock.patch('doord.Tag.authenticate')
    def test_iter_not_keyholder(self, mock_tag_auth):
        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = 1  # the space switch is at pullup (space closed)
        mock_tag_auth.return_value = (True, [4])  # just member
        self.ds._iter()
        # the door was not opened
        for call in RPi.GPIO.call_history:
            assert call['pin'] != self.ds.DOOR_IO
        assert mock_tag_auth.call_count == 1

    @mock.patch('doord.Tag.authenticate')
    @mock.patch('doord.EntryDatabase.server_poll')
    def test_iter_keyholder_space_closed(self, mock_db_poll, mock_tag_auth):
        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = 1  # the space switch is at pullup (space closed)
        mock_tag_auth.return_value = (True, [4, 5])
        mock_db_poll.return_value = None
        self.ds._iter()
        door_opened = False
        led_calls = 0
        led = RPi.GPIO.LOW
        for call in RPi.GPIO.call_history:
            if call['pin'] == self.ds.DOOR_IO:
                assert call['value'] == RPi.GPIO.HIGH
                door_opened = True
            elif call['pin'] == self.ds.LED_IO:
                led_calls += 1
                led = call['value']
            else:
                assert False
        assert led_calls == 2
        assert led == RPi.GPIO.LOW
        assert door_opened
        assert mock_tag_auth.call_count == 1
        assert mock_db_poll.call_count == 1

    @mock.patch('doord.Tag.authenticate')
    def test_iter_keyholder_space_open(self, mock_tag_auth):
        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = 0  # the space switch is at gnd (space open)
        mock_tag_auth.return_value = (True, [4, 5])
        self.ds._iter()
        door_opened = False
        for call in RPi.GPIO.call_history:
            if call['pin'] == self.ds.DOOR_IO:
                assert call['value'] == RPi.GPIO.HIGH
                door_opened = True
        assert door_opened
        assert mock_tag_auth.call_count == 1

    @mock.patch('doord.Tag.authenticate')
    def test_iter_member_space_closed(self, mock_tag_auth):
        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = 1  # the space switch is at pullup (space closed)
        mock_tag_auth.return_value = (True, [4])  # just member
        self.ds._iter()
        # the door was not opened
        for call in RPi.GPIO.call_history:
            assert call['pin'] != self.ds.DOOR_IO
        assert mock_tag_auth.call_count == 1

    @mock.patch('doord.Tag.authenticate')
    def test_iter_member_space_open(self, mock_tag_auth):
        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = 0  # the space switch is at gnd (space open)
        mock_tag_auth.return_value = (True, [4])  # just member
        self.ds._iter()
        door_opened = False
        for call in RPi.GPIO.call_history:
            if call['pin'] == self.ds.DOOR_IO:
                assert call['value'] == RPi.GPIO.HIGH
                door_opened = True
        assert door_opened
        assert mock_tag_auth.call_count == 1

    def test_door_closed_on_init(self):
        door_closed = False
        for call in RPi.GPIO.call_history:
            if call['method'] == 'output' and call['pin'] == self.ds.DOOR_IO:
                assert call['value'] == RPi.GPIO.LOW
                door_closed = True
        assert door_closed

    def test_door_closed_after_opened(self):
        RPi.GPIO.call_history = []
        self.ds.door_opened = os.times()[4] - 10
        self.ds.nfc.return_code = self.ds.nfc.MI_NOTAGERR
        self.ds._iter()
        assert len(RPi.GPIO.call_history) == 1
        assert RPi.GPIO.call_history[0]['pin'] == self.ds.DOOR_IO
        assert RPi.GPIO.call_history[0]['value'] == RPi.GPIO.LOW

    @mock.patch('os.times')
    def test_door_closes_from_start(self, mock_time):
        RPi.GPIO.call_history = []
        mock_time.side_effect = -50
        self.ds.door_opened = -100
        self.ds.nfc.return_code = self.ds.nfc.MI_NOTAGERR
        self.ds._iter()
        assert len(RPi.GPIO.call_history) == 1
        assert RPi.GPIO.call_history[0]['pin'] == self.ds.DOOR_IO
        assert RPi.GPIO.call_history[0]['value'] == RPi.GPIO.LOW

    # os.times()[4] can be negative, which caused problems in the past
    # check we initialise event times to the startup value of os.tmes()[4]
    def test_event_times_init(self):
        assert os.times()[4] - 1 < self.ds.door_opened <= os.times()[4]
        assert os.times()[4] - 1 < self.ds.last_server_poll <= os.times()[4]
        assert os.times()[4] - 1 < self.ds.led_last_time <= os.times()[4]

    @mock.patch('doord.EntryDatabase.server_poll')
    def test_server_iter_no_need(self, mock_server_poll):
        print dir(self.ds)
        self.ds._server_iter()
        mock_server_poll.assert_not_called()

    @mock.patch('doord.EntryDatabase.server_poll')
    def test_server_iter(self, mock_server_poll):
        self.ds.last_server_poll = os.times()[4] - self.ds.SERVER_POLL - 1
        mock_server_poll.return_value = None
        self.ds._server_iter()
        assert mock_server_poll.call_count == 1

    def test_led_logic(self):
        self.ds.LED_HEARTBEAT_TIMES = (0.2, 5)
        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = {self.ds.DOOR_IO: [0], self.ds.LED_IO: [0]}
        self.ds.led_last_time = os.times()[4] - 4.9
        self.ds._led_iter()
        for call in RPi.GPIO.call_history:
            assert call['method'] != 'ooutput'

        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = {self.ds.DOOR_IO: [0], self.ds.LED_IO: [0]}
        self.ds.led_last_time = os.times()[4] - 5.1
        self.ds._led_iter()
        for call in RPi.GPIO.call_history:
            if call['method'] == 'output':
                assert call['value'] == RPi.GPIO.HIGH

        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = {self.ds.DOOR_IO: [0], self.ds.LED_IO: [1]}
        self.ds.led_last_time = os.times()[4] - 0.1
        self.ds._led_iter()
        for call in RPi.GPIO.call_history:
            assert call['method'] != 'ooutput'

        RPi.GPIO.call_history = []
        RPi.GPIO.output_value = {self.ds.DOOR_IO: [0], self.ds.LED_IO: [1]}
        self.ds.led_last_time = os.times()[4] - 0.3
        self.ds._led_iter()
        for call in RPi.GPIO.call_history:
            if call['method'] == 'output':
                assert call['value'] == RPi.GPIO.LOW

    @mock.patch('doord.Tag.authenticate')
    @mock.patch('doord.EntryDatabase.server_poll')
    def test_magic_tag_server_poll(self, mock_server_poll, mock_auth):
        self.ds.MAGIC_TAGS['fedcba98'] = 'pull_db'
        mock_server_poll.return_value = None
        self.ds._iter()
        mock_auth.assert_not_called()

    @mock.patch('doord.Tag.authenticate')
    @mock.patch('doord.DoorService.init_tag')
    def test_magic_tag_init(self, mock_init, mock_auth):
        self.ds.MAGIC_TAGS['fedcba98'] = 'init_tag'
        mock_init.return_value = None
        self.ds._iter()
        mock_auth.assert_not_called()
        assert mock_init.called

    @mock.patch('doord.Tag.initialize')
    def test_init_tag_dont_init_magic(self, mock_init):
        self.ds.MAGIC_TAGS['fedcba98'] = 'init_tag'
        self.ds.MAGIC_TAG_TIMEOUT = 0.1
        self.ds.init_tag()
        mock_init.assert_not_called()

    @mock.patch('doord.Tag.initialize')
    def test_init_tag_timeout(self, mock_init):
        self.ds.nfc.return_code = self.ds.nfc.MI_NOTAGERR
        self.ds.MAGIC_TAG_TIMEOUT = 0.1
        self.ds.init_tag()
        mock_init.assert_not_called()

    @mock.patch('doord.Tag.initialize')
    def test_init_tag(self, mock_init):
        mock_init.return_value = None
        self.ds.init_tag()
        assert mock_init.call_count == 1

    @mock.patch('doord.Tag.initialize')
    def test_init_tag_fail(self, mock_init):
        mock_init.side_effect = doord.TagException('Well that could have gone better')
        self.ds.init_tag()
        assert mock_init.call_count == 1


class TestTag(unittest.TestCase):

    # Mock patch does not like the mocked stub module at all, fiddle with the stub instead
    def setUp(self):
        self.nfc = MFRC522.MFRC522()
        self.tag = doord.Tag([0xfe, 0xdc, 0xba, 0x98], self.nfc, None)

    def tearDown(self):
        try:
            del(self.tag)
        except:
            pass
        del(self.nfc)

    def test_read_sector(self):
        self.nfc.call_history = []
        self.nfc.sector_content = self.nfc.DEFAULT_SECTOR_CONTENT
        backdata = self.tag.read_sector(1, [1, 2, 3, 4, 5, 6], 'a keyspec')
        assert len(self.nfc.call_history) == 2
        assert self.nfc.call_history[0]['method'] == 'Auth_Sector'
        assert self.nfc.call_history[0]['sector'] == 1
        assert self.nfc.call_history[0]['keyspec'] == 'a keyspec'
        assert self.nfc.call_history[1]['method'] == 'Read_Sector'
        assert self.nfc.call_history[1]['sector'] == 1
        assert backdata == self.nfc.DEFAULT_SECTOR_CONTENT

    def test_read_sector_auth_fail(self):
        self.nfc.call_history = []
        self.nfc.return_code = self.nfc.MI_ERR
        try:
            backdata = self.tag.read_sector(1, [1, 2, 3, 4, 5, 6], 'a keyspec')
            assert False
        except doord.TagException:
            pass
        assert len(self.nfc.call_history) == 1

    def test_read_sector_read_fail(self):
        self.nfc.call_history = []
        try:
            backdata = self.tag.read_sector(1, [1, 2, 3, 4, 5, 6], 'a keyspec')
            assert False
        except doord.TagException:
            pass
        assert len(self.nfc.call_history) == 2

    def test_configure_sector(self):
        self.nfc.call_history = []
        self.tag.configure_sector(1,
                                  [1, 2, 3, 4, 5, 6],
                                  'a keyspec',
                                  [1, 2, 3, 4, 5, 6],
                                  self.tag.SECTOR_LOCK_BYTES,
                                  [6, 5, 4, 3, 2, 1])
        assert len(self.nfc.call_history) == 2
        assert self.nfc.call_history[0]['method'] == 'Auth_Sector'
        assert self.nfc.call_history[0]['sector'] == 1
        assert self.nfc.call_history[0]['keyspec'] == 'a keyspec'
        assert self.nfc.call_history[1]['method'] == 'Write_Block'
        assert self.nfc.call_history[1]['block'] == 7
        assert self.nfc.call_history[1]['block_content'] == [1, 2, 3, 4, 5, 6] + \
            self.tag.SECTOR_LOCK_BYTES + [6, 5, 4, 3, 2, 1]

    def test_configure_sector_auth_fail(self):
        self.nfc.call_history = []
        self.nfc.return_code = self.nfc.MI_ERR
        try:
            self.tag.configure_sector(1,
                                      [1, 2, 3, 4, 5, 6],
                                      'a keyspec',
                                      [1, 2, 3, 4, 5, 6],
                                      self.tag.SECTOR_LOCK_BYTES,
                                      [6, 5, 4, 3, 2, 1])
            assert False
        except doord.TagException:
            pass
        assert len(self.nfc.call_history) == 1

    def test_configure_sector_write_fail(self):
        self.nfc.call_history = []
        self.nfc.return_code = [self.nfc.MI_OK, self.nfc.MI_ERR]
        try:
            self.tag.configure_sector(1,
                                      [1, 2, 3, 4, 5, 6],
                                      'a keyspec',
                                      [1, 2, 3, 4, 5, 6],
                                      self.tag.SECTOR_LOCK_BYTES,
                                      [6, 5, 4, 3, 2, 1])
            assert False
        except doord.TagException:
            pass
        assert len(self.nfc.call_history) == 2

    def test_select_tag_on_init(self):
        print self.nfc.call_history
        assert self.nfc.call_history[0]['method'] == 'MFRC522_SelectTag'
        assert self.nfc.call_history[0]['uid'] == self.tag.uid

    def test_stop_crypto_on_del(self):
        del(self.tag)
        assert self.nfc.call_history[-1]['method'] == 'MFRC522_StopCrypto1'

    def test_get_printable_uid(self):
        assert str(self.tag) == 'fedcba98'

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.log_auth')
    def test_log_auth(self, mock_db_log, mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_log.return_value = None
        self.tag.log_auth('DOOR1', 'DENIED')
        mock_db_log.assert_called_once_with(str(self.tag), 'DOOR1', 'DENIED')

    def test_write_sector(self):
        self.nfc.call_history = []
        self.tag.write_sector(2, [2, 3, 4, 5, 6, 7],
                              'some keyspec',
                              base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg='),
                              42)
        assert len(self.nfc.call_history) == 4
        assert self.nfc.call_history[0]['method'] == 'Auth_Sector'
        assert self.nfc.call_history[0]['sector'] == 2
        assert self.nfc.call_history[1]['method'] == 'Write_Block'
        assert self.nfc.call_history[1]['block'] == 8
        assert self.nfc.call_history[1]['block_content'][0:2] == [0, 42]  # plaintext count
        assert self.nfc.call_history[1]['block_content'][2] == 2  # bcrypt default, may change
        assert self.nfc.call_history[1]['block_content'][3] == 8  # doord config, may be changed safely at any time
        assert self.nfc.call_history[2]['method'] == 'Write_Block'
        assert self.nfc.call_history[2]['block'] == 9
        assert self.nfc.call_history[3]['method'] == 'Write_Block'
        assert self.nfc.call_history[3]['block'] == 10
        assert self.nfc.call_history[3]['block_content'][12:14] == [0, 0]  # reserved
        assert (self.nfc.call_history[3]['block_content'][14] << 8) + self.nfc.call_history[3]['block_content'][15] == \
            crc16.crc16xmodem("".join(map(chr, self.nfc.call_history[1]['block_content'] +
                              self.nfc.call_history[2]['block_content'] +
                              self.nfc.call_history[3]['block_content'][0:14])))  # crc
        assert self.tag.validate_sector(self.nfc.call_history[1]['block_content'] +
                                        self.nfc.call_history[2]['block_content'] +
                                        self.nfc.call_history[3]['block_content'],
                                        base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')) == 42  # sector validates through tested method

    def test_write_sector_fail_auth(self):
        self.nfc.call_history = []
        self.nfc.return_code = self.nfc.MI_ERR
        try:
            self.tag.write_sector(2, [2, 3, 4, 5, 6, 7],
                                  'some keyspec',
                                  base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg='),
                                  42)
            assert False
        except doord.TagException:
            pass
        assert len(self.nfc.call_history) == 1

    def test_write_sector_write_fail(self):
        self.nfc.call_history = []
        self.nfc.return_code = [self.nfc.MI_OK, self.nfc.MI_ERR]
        try:
            self.tag.write_sector(2, [2, 3, 4, 5, 6, 7],
                                  'some keyspec',
                                  base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg='),
                                  42)
            assert False
        except doord.TagException:
            pass
        assert len(self.nfc.call_history) == 2

    def test_write_sector_later_write_fail(self):
        self.nfc.call_history = []
        self.nfc.return_code = [self.nfc.MI_OK, self.nfc.MI_OK, self.nfc.MI_OK, self.nfc.MI_ERR]
        try:
            self.tag.write_sector(2, [2, 3, 4, 5, 6, 7],
                                  'some keyspec',
                                  base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg='),
                                  42)
            assert False
        except doord.TagException:
            pass
        assert len(self.nfc.call_history) == 4

    def test_validate_sector(self):
        sector_data = [0x00, 0x2a, 0x02, 0x08, 0xdd, 0x95, 0xb7, 0x02, 0x03, 0x36, 0x91, 0x86, 0xec, 0xbb, 0x94, 0x7f,
                       0xfc, 0x08, 0x6e, 0x0b, 0xd8, 0x89, 0xbe, 0xad, 0x0b, 0xa9, 0xb3, 0xe4, 0x0f, 0xbe, 0xed, 0x44,
                       0xe5, 0x54, 0xb0, 0xad, 0x2b, 0x44, 0x7a, 0x87, 0xf9, 0x10, 0x7f, 0x08, 0x00, 0x00, 0xc1, 0xe6]
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        assert self.tag.validate_sector(sector_data, secret) == 42

    def test_validate_next_sector(self):
        sector_data = [0x00, 0x2b, 0x02, 0x08, 0x01, 0x75, 0x6e, 0x78, 0x37, 0xd6, 0x82, 0x0c, 0x0a, 0xee, 0x9f, 0xb3,
                       0x61, 0xa6, 0x32, 0x02, 0xac, 0x17, 0xa3, 0x49, 0x6f, 0x74, 0x32, 0xfb, 0x05, 0xb6, 0xf5, 0x3d,
                       0x2a, 0x38, 0x04, 0x88, 0x06, 0xd4, 0x54, 0xe0, 0xb5, 0x5c, 0x29, 0x14, 0x00, 0x00, 0x9d, 0xc9]
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        assert self.tag.validate_sector(sector_data, secret) == 43

    def test_validate_checksum_error(self):
        sector_data = [0x00, 0x2a, 0x02, 0x08, 0xdd, 0x95, 0xb7, 0x02, 0x03, 0x36, 0x91, 0x86, 0xec, 0xbb, 0x94, 0x7f,
                       0xfc, 0x08, 0x6e, 0x0b, 0xd8, 0x89, 0xbe, 0xad, 0x0b, 0xa9, 0xb3, 0xe4, 0x0f, 0xbe, 0xed, 0x45,  # 1-bit error
                       0xe5, 0x54, 0xb0, 0xad, 0x2b, 0x44, 0x7a, 0x87, 0xf9, 0x10, 0x7f, 0x08, 0x00, 0x00, 0xc1, 0xe6]
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        try:
            assert self.tag.validate_sector(sector_data, secret)
            assert False
        except doord.TagException:
            pass

    def test_validate_count_mismatch(self):
        #                    # v--- count of 41 in a 42 sector
        sector_data = [0x00, 0x29, 0x02, 0x08, 0xdd, 0x95, 0xb7, 0x02, 0x03, 0x36, 0x91, 0x86, 0xec, 0xbb, 0x94, 0x7f,
                       0xfc, 0x08, 0x6e, 0x0b, 0xd8, 0x89, 0xbe, 0xad, 0x0b, 0xa9, 0xb3, 0xe4, 0x0f, 0xbe, 0xed, 0x44,
                       0xe5, 0x54, 0xb0, 0xad, 0x2b, 0x44, 0x7a, 0x87, 0xf9, 0x10, 0x7f, 0x08, 0x00, 0x00, 0xc1, 0xe6]
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        try:
            assert self.tag.validate_sector(sector_data, secret)
            assert False
        except doord.TagException:
            pass

    def test_validate_algorithm_mismatch(self):
        #                           # v--- different bcrypt algorithm from sector
        sector_data = [0x00, 0x2a, 0x01, 0x08, 0xdd, 0x95, 0xb7, 0x02, 0x03, 0x36, 0x91, 0x86, 0xec, 0xbb, 0x94, 0x7f,
                       0xfc, 0x08, 0x6e, 0x0b, 0xd8, 0x89, 0xbe, 0xad, 0x0b, 0xa9, 0xb3, 0xe4, 0x0f, 0xbe, 0xed, 0x44,
                       0xe5, 0x54, 0xb0, 0xad, 0x2b, 0x44, 0x7a, 0x87, 0xf9, 0x10, 0x7f, 0x08, 0x00, 0x00, 0xc1, 0xe6]
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        try:
            assert self.tag.validate_sector(sector_data, secret)
            assert False
        except doord.TagException:
            pass

    def test_validate_future_algorithm(self):
        #                          # v--- unknown bcrypt algorithm
        sector_data = [0x00, 0x2a, 0xf2, 0x08, 0xdd, 0x95, 0xb7, 0x02, 0x03, 0x36, 0x91, 0x86, 0xec, 0xbb, 0x94, 0x7f,
                       0xfc, 0x08, 0x6e, 0x0b, 0xd8, 0x89, 0xbe, 0xad, 0x0b, 0xa9, 0xb3, 0xe4, 0x0f, 0xbe, 0xed, 0x44,
                       0xe5, 0x54, 0xb0, 0xad, 0x2b, 0x44, 0x7a, 0x87, 0xf9, 0x10, 0x7f, 0x08, 0x00, 0x00, 0xc1, 0xe6]
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        try:
            assert self.tag.validate_sector(sector_data, secret)
            assert False
        except doord.TagException:
            pass

    def test_validate_work_factor_mismatch(self):
        #                                 # v--- different bcrypt work factor from sector
        sector_data = [0x00, 0x2a, 0x02, 0x0c, 0xdd, 0x95, 0xb7, 0x02, 0x03, 0x36, 0x91, 0x86, 0xec, 0xbb, 0x94, 0x7f,
                       0xfc, 0x08, 0x6e, 0x0b, 0xd8, 0x89, 0xbe, 0xad, 0x0b, 0xa9, 0xb3, 0xe4, 0x0f, 0xbe, 0xed, 0x44,
                       0xe5, 0x54, 0xb0, 0xad, 0x2b, 0x44, 0x7a, 0x87, 0xf9, 0x10, 0x7f, 0x08, 0x00, 0x00, 0xc1, 0xe6]
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        try:
            assert self.tag.validate_sector(sector_data, secret)
            assert False
        except doord.TagException:
            pass

    def test_validate_corrupt_reserved_1(self):
        sector_data = [0x00, 0x2a, 0x02, 0x08, 0xdd, 0x95, 0xb7, 0x02, 0x03, 0x36, 0x91, 0x86, 0xec, 0xbb, 0x94, 0x7f,
                       0xfc, 0x08, 0x6e, 0x0b, 0xd8, 0x89, 0xbe, 0xad, 0x0b, 0xa9, 0xb3, 0xe4, 0x0f, 0xbe, 0xed, 0x44,
                       0xe5, 0x54, 0xb0, 0xad, 0x2b, 0x44, 0x7a, 0x87, 0xf9, 0x10, 0x7f, 0x08, 0x01, 0x00, 0xc1, 0xe6]
        #                                                                                       # ^--- here
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        try:
            assert self.tag.validate_sector(sector_data, secret)
            assert False
        except doord.TagException:
            pass

    def test_validate_corrupt_reserved_2(self):
        sector_data = [0x00, 0x2a, 0x02, 0x08, 0xdd, 0x95, 0xb7, 0x02, 0x03, 0x36, 0x91, 0x86, 0xec, 0xbb, 0x94, 0x7f,
                       0xfc, 0x08, 0x6e, 0x0b, 0xd8, 0x89, 0xbe, 0xad, 0x0b, 0xa9, 0xb3, 0xe4, 0x0f, 0xbe, 0xed, 0x44,
                       0xe5, 0x54, 0xb0, 0xad, 0x2b, 0x44, 0x7a, 0x87, 0xf9, 0x10, 0x7f, 0x08, 0x00, 0x01, 0xc1, 0xe6]
        #                                                                                               ^--- here
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        try:
            assert self.tag.validate_sector(sector_data, secret)
            assert False
        except doord.TagException:
            pass

    def test_validate_blank_sector(self):
        sector_data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        secret = base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg=')
        try:
            assert self.tag.validate_sector(sector_data, secret)
            assert False
        except doord.TagException:
            pass

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate(self,
                          mock_db_get_roles,
                          mock_db_set_count,
                          mock_write_sector,
                          mock_validate_sector,
                          mock_read_sector,
                          mock_db_get_secret_b,
                          mock_db_get_keyb_b,
                          mock_db_get_sector_b,
                          mock_db_get_secret_a,
                          mock_db_get_keyb_a,
                          mock_db_get_sector_a,
                          mock_db_get_count,
                          mock_db_get_name,
                          mock_db_get_user,
                          mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [41, 42, 43]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.return_value = [2, 4, 5]
        assert self.tag.authenticate() == (True, [2, 4, 5])
        mock_write_sector.assert_called_once_with(1, [1, 2, 3, 4, 5, 6], self.nfc.PICC_AUTHENT1B, 'doesntmatter', 43)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_again(self,
                                mock_db_get_roles,
                                mock_db_set_count,
                                mock_write_sector,
                                mock_validate_sector,
                                mock_read_sector,
                                mock_db_get_secret_b,
                                mock_db_get_keyb_b,
                                mock_db_get_sector_b,
                                mock_db_get_secret_a,
                                mock_db_get_keyb_a,
                                mock_db_get_sector_a,
                                mock_db_get_count,
                                mock_db_get_name,
                                mock_db_get_user,
                                mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 43
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [43, 42, 44]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.return_value = [2, 4, 5]
        assert self.tag.authenticate() == (True, [2, 4, 5])
        mock_write_sector.assert_called_once_with(2, [2, 3, 4, 5, 6, 7], self.nfc.PICC_AUTHENT1B, 'dontcare', 44)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_ahead_of_count(self,
                                         mock_db_get_roles,
                                         mock_db_set_count,
                                         mock_write_sector,
                                         mock_validate_sector,
                                         mock_read_sector,
                                         mock_db_get_secret_b,
                                         mock_db_get_keyb_b,
                                         mock_db_get_sector_b,
                                         mock_db_get_secret_a,
                                         mock_db_get_keyb_a,
                                         mock_db_get_sector_a,
                                         mock_db_get_count,
                                         mock_db_get_name,
                                         mock_db_get_user,
                                         mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [81, 82, 83]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.return_value = [2, 4, 5]
        assert self.tag.authenticate() == (True, [2, 4, 5])

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_ahead_of_count_alt(self,
                                             mock_db_get_roles,
                                             mock_db_set_count,
                                             mock_write_sector,
                                             mock_validate_sector,
                                             mock_read_sector,
                                             mock_db_get_secret_b,
                                             mock_db_get_keyb_b,
                                             mock_db_get_sector_b,
                                             mock_db_get_secret_a,
                                             mock_db_get_keyb_a,
                                             mock_db_get_sector_a,
                                             mock_db_get_count,
                                             mock_db_get_name,
                                             mock_db_get_user,
                                             mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [83, 82, 84]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.return_value = [2, 4, 5]
        assert self.tag.authenticate() == (True, [2, 4, 5])

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_over_spced(self,
                                     mock_db_get_roles,
                                     mock_db_set_count,
                                     mock_write_sector,
                                     mock_validate_sector,
                                     mock_read_sector,
                                     mock_db_get_secret_b,
                                     mock_db_get_keyb_b,
                                     mock_db_get_sector_b,
                                     mock_db_get_secret_a,
                                     mock_db_get_keyb_a,
                                     mock_db_get_sector_a,
                                     mock_db_get_count,
                                     mock_db_get_name,
                                     mock_db_get_user,
                                     mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [12, 42, 43]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.return_value = [2, 4, 5]
        assert self.tag.authenticate() == (True, [2, 4, 5])
        mock_write_sector.assert_called_once_with(1, [1, 2, 3, 4, 5, 6], self.nfc.PICC_AUTHENT1B, 'doesntmatter', 43)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_overspaced_alt(self,
                                         mock_db_get_roles,
                                         mock_db_set_count,
                                         mock_write_sector,
                                         mock_validate_sector,
                                         mock_read_sector,
                                         mock_db_get_secret_b,
                                         mock_db_get_keyb_b,
                                         mock_db_get_sector_b,
                                         mock_db_get_secret_a,
                                         mock_db_get_keyb_a,
                                         mock_db_get_sector_a,
                                         mock_db_get_count,
                                         mock_db_get_name,
                                         mock_db_get_user,
                                         mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 43
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [43, 12, 44]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.return_value = [2, 4, 5]
        assert self.tag.authenticate() == (True, [2, 4, 5])
        mock_write_sector.assert_called_once_with(2, [2, 3, 4, 5, 6, 7], self.nfc.PICC_AUTHENT1B, 'dontcare', 44)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_bad_sector_a(self,
                                       mock_db_get_roles,
                                       mock_db_set_count,
                                       mock_write_sector,
                                       mock_validate_sector,
                                       mock_read_sector,
                                       mock_db_get_secret_b,
                                       mock_db_get_keyb_b,
                                       mock_db_get_sector_b,
                                       mock_db_get_secret_a,
                                       mock_db_get_keyb_a,
                                       mock_db_get_sector_a,
                                       mock_db_get_count,
                                       mock_db_get_name,
                                       mock_db_get_user,
                                       mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [doord.TagException('This sector is junk.'), 42, 43]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.return_value = [2, 4, 5]
        assert self.tag.authenticate() == (True, [2, 4, 5])
        mock_write_sector.assert_called_once_with(1, [1, 2, 3, 4, 5, 6], self.nfc.PICC_AUTHENT1B, 'doesntmatter', 43)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_bad_sector_b(self,
                                       mock_db_get_roles,
                                       mock_db_set_count,
                                       mock_write_sector,
                                       mock_validate_sector,
                                       mock_read_sector,
                                       mock_db_get_secret_b,
                                       mock_db_get_keyb_b,
                                       mock_db_get_sector_b,
                                       mock_db_get_secret_a,
                                       mock_db_get_keyb_a,
                                       mock_db_get_sector_a,
                                       mock_db_get_count,
                                       mock_db_get_name,
                                       mock_db_get_user,
                                       mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 43
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [43, doord.TagException('Splat that!'), 44]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.return_value = [2, 4, 5]
        assert self.tag.authenticate() == (True, [2, 4, 5])
        mock_write_sector.assert_called_once_with(2, [2, 3, 4, 5, 6, 7], self.nfc.PICC_AUTHENT1B, 'dontcare', 44)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_both_sectors_bad(self,
                                           mock_db_get_roles,
                                           mock_db_set_count,
                                           mock_write_sector,
                                           mock_validate_sector,
                                           mock_read_sector,
                                           mock_db_get_secret_b,
                                           mock_db_get_keyb_b,
                                           mock_db_get_sector_b,
                                           mock_db_get_secret_a,
                                           mock_db_get_keyb_a,
                                           mock_db_get_sector_a,
                                           mock_db_get_count,
                                           mock_db_get_name,
                                           mock_db_get_user,
                                           mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = doord.TagException('Bad sector you got there')
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_not_called()

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_cloned_tag(self,
                                     mock_db_get_roles,
                                     mock_db_set_count,
                                     mock_write_sector,
                                     mock_validate_sector,
                                     mock_read_sector,
                                     mock_db_get_secret_b,
                                     mock_db_get_keyb_b,
                                     mock_db_get_sector_b,
                                     mock_db_get_secret_a,
                                     mock_db_get_keyb_a,
                                     mock_db_get_sector_a,
                                     mock_db_get_count,
                                     mock_db_get_name,
                                     mock_db_get_user,
                                     mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 43
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [41, 42]
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_not_called()

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_cloned_tag_alt(self,
                                         mock_db_get_roles,
                                         mock_db_set_count,
                                         mock_write_sector,
                                         mock_validate_sector,
                                         mock_read_sector,
                                         mock_db_get_secret_b,
                                         mock_db_get_keyb_b,
                                         mock_db_get_sector_b,
                                         mock_db_get_secret_a,
                                         mock_db_get_keyb_a,
                                         mock_db_get_sector_a,
                                         mock_db_get_count,
                                         mock_db_get_name,
                                         mock_db_get_user,
                                         mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 44
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [43, 42]
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_not_called()

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_alien_tag(self,
                                    mock_write_sector,
                                    mock_db_get_user,
                                    mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.side_effect = doord.EntryDatabaseException("Unkown tag")
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_not_called()

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_unassigned_tag(self,
                                         mock_write_sector,
                                         mock_db_get_user,
                                         mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.side_effect = doord.EntryDatabaseException("Unassigned tag")
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_not_called()

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_get_user_error(self,
                                         mock_write_sector,
                                         mock_db_get_user,
                                         mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.side_effect = doord.EntryDatabaseException("Something else")
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_not_called()

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticatei_read_error_a(self,
                                        mock_write_sector,
                                        mock_read_sector,
                                        mock_db_get_secret_b,
                                        mock_db_get_keyb_b,
                                        mock_db_get_sector_b,
                                        mock_db_get_secret_a,
                                        mock_db_get_keyb_a,
                                        mock_db_get_sector_a,
                                        mock_db_get_count,
                                        mock_db_get_name,
                                        mock_db_get_user,
                                        mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.side_effect = doord.TagException('READERR')
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_not_called()

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticatei_read_error_b(self,
                                        mock_write_sector,
                                        mock_read_sector,
                                        mock_db_get_secret_b,
                                        mock_db_get_keyb_b,
                                        mock_db_get_sector_b,
                                        mock_db_get_secret_a,
                                        mock_db_get_keyb_a,
                                        mock_db_get_sector_a,
                                        mock_db_get_count,
                                        mock_db_get_name,
                                        mock_db_get_user,
                                        mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.side_effect = ['anything', doord.TagException('READERR')]
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_not_called()

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticatei_write_error(self,
                                       mock_write_sector,
                                       mock_validate_sector,
                                       mock_read_sector,
                                       mock_db_get_secret_b,
                                       mock_db_get_keyb_b,
                                       mock_db_get_sector_b,
                                       mock_db_get_secret_a,
                                       mock_db_get_keyb_a,
                                       mock_db_get_sector_a,
                                       mock_db_get_count,
                                       mock_db_get_name,
                                       mock_db_get_user,
                                       mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [41, 42, 43]
        mock_write_sector.side_effect = doord.TagException('Cant write joined up')
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_called_once_with(1, [1, 2, 3, 4, 5, 6], self.nfc.PICC_AUTHENT1B, 'doesntmatter', 43)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_redback_error(self,
                                        mock_write_sector,
                                        mock_validate_sector,
                                        mock_read_sector,
                                        mock_db_get_secret_b,
                                        mock_db_get_keyb_b,
                                        mock_db_get_sector_b,
                                        mock_db_get_secret_a,
                                        mock_db_get_keyb_a,
                                        mock_db_get_sector_a,
                                        mock_db_get_count,
                                        mock_db_get_name,
                                        mock_db_get_user,
                                        mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.side_effect = ['irrelevant', 'irrelephant', doord.TagException('OMG')]
        mock_validate_sector.side_effect = [41, 42, 43]
        mock_write_sector.return_value = None
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_called_once_with(1, [1, 2, 3, 4, 5, 6], self.nfc.PICC_AUTHENT1B, 'doesntmatter', 43)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_redback_validte_error(self,
                                                mock_write_sector,
                                                mock_validate_sector,
                                                mock_read_sector,
                                                mock_db_get_secret_b,
                                                mock_db_get_keyb_b,
                                                mock_db_get_sector_b,
                                                mock_db_get_secret_a,
                                                mock_db_get_keyb_a,
                                                mock_db_get_sector_a,
                                                mock_db_get_count,
                                                mock_db_get_name,
                                                mock_db_get_user,
                                                mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.side_effect = 'irrelevant'
        mock_validate_sector.side_effect = [41, 42, doord.TagException('INVALID')]
        mock_write_sector.return_value = None
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_called_once_with(1, [1, 2, 3, 4, 5, 6], self.nfc.PICC_AUTHENT1B, 'doesntmatter', 43)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_redback_not_updated(self,
                                              mock_write_sector,
                                              mock_validate_sector,
                                              mock_read_sector,
                                              mock_db_get_secret_b,
                                              mock_db_get_keyb_b,
                                              mock_db_get_sector_b,
                                              mock_db_get_secret_a,
                                              mock_db_get_keyb_a,
                                              mock_db_get_sector_a,
                                              mock_db_get_count,
                                              mock_db_get_name,
                                              mock_db_get_user,
                                              mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.side_effect = 'irrelevant'
        mock_validate_sector.side_effect = [41, 42, 41]
        mock_write_sector.return_value = None
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_called_once_with(1, [1, 2, 3, 4, 5, 6], self.nfc.PICC_AUTHENT1B, 'doesntmatter', 43)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticatei_write_error_alt(self,
                                           mock_write_sector,
                                           mock_validate_sector,
                                           mock_read_sector,
                                           mock_db_get_secret_b,
                                           mock_db_get_keyb_b,
                                           mock_db_get_sector_b,
                                           mock_db_get_secret_a,
                                           mock_db_get_keyb_a,
                                           mock_db_get_sector_a,
                                           mock_db_get_count,
                                           mock_db_get_name,
                                           mock_db_get_user,
                                           mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 43
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [43, 42, 44]
        mock_write_sector.side_effect = doord.TagException('Cant write joined up')
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_called_once_with(2, [2, 3, 4, 5, 6, 7], self.nfc.PICC_AUTHENT1B, 'dontcare', 44)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_redback_error_alt(self,
                                            mock_write_sector,
                                            mock_validate_sector,
                                            mock_read_sector,
                                            mock_db_get_secret_b,
                                            mock_db_get_keyb_b,
                                            mock_db_get_sector_b,
                                            mock_db_get_secret_a,
                                            mock_db_get_keyb_a,
                                            mock_db_get_sector_a,
                                            mock_db_get_count,
                                            mock_db_get_name,
                                            mock_db_get_user,
                                            mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 43
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.side_effect = ['irrelevant', 'irrelephant', doord.TagException('OMG')]
        mock_validate_sector.side_effect = [43, 42, 44]
        mock_write_sector.return_value = None
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_called_once_with(2, [2, 3, 4, 5, 6, 7], self.nfc.PICC_AUTHENT1B, 'dontcare', 44)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_redback_validte_error_alt(self,
                                                    mock_write_sector,
                                                    mock_validate_sector,
                                                    mock_read_sector,
                                                    mock_db_get_secret_b,
                                                    mock_db_get_keyb_b,
                                                    mock_db_get_sector_b,
                                                    mock_db_get_secret_a,
                                                    mock_db_get_keyb_a,
                                                    mock_db_get_sector_a,
                                                    mock_db_get_count,
                                                    mock_db_get_name,
                                                    mock_db_get_user,
                                                    mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 43
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.side_effect = 'irrelevant'
        mock_validate_sector.side_effect = [43, 42, doord.TagException('INVALID')]
        mock_write_sector.return_value = None
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_called_once_with(2, [2, 3, 4, 5, 6, 7], self.nfc.PICC_AUTHENT1B, 'dontcare', 44)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    def test_authenticate_redback_not_updated_alt(self,
                                                  mock_write_sector,
                                                  mock_validate_sector,
                                                  mock_read_sector,
                                                  mock_db_get_secret_b,
                                                  mock_db_get_keyb_b,
                                                  mock_db_get_sector_b,
                                                  mock_db_get_secret_a,
                                                  mock_db_get_keyb_a,
                                                  mock_db_get_sector_a,
                                                  mock_db_get_count,
                                                  mock_db_get_name,
                                                  mock_db_get_user,
                                                  mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 43
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.side_effect = 'irrelevant'
        mock_validate_sector.side_effect = [43, 42, 42]
        mock_write_sector.return_value = None
        assert self.tag.authenticate() == (False, [])
        mock_write_sector.assert_called_once_with(2, [2, 3, 4, 5, 6, 7], self.nfc.PICC_AUTHENT1B, 'dontcare', 44)

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.get_tag_user')
    @mock.patch('doord.EntryDatabase.get_user_name')
    @mock.patch('doord.EntryDatabase.get_tag_count')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.get_tag_sector_b_secret')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.get_user_roles')
    def test_authenticate_get_roles_fail(self,
                                         mock_db_get_roles,
                                         mock_db_set_count,
                                         mock_write_sector,
                                         mock_validate_sector,
                                         mock_read_sector,
                                         mock_db_get_secret_b,
                                         mock_db_get_keyb_b,
                                         mock_db_get_sector_b,
                                         mock_db_get_secret_a,
                                         mock_db_get_keyb_a,
                                         mock_db_get_sector_a,
                                         mock_db_get_count,
                                         mock_db_get_name,
                                         mock_db_get_user,
                                         mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_db_get_user.return_value = '00003'
        mock_db_get_name.return_value = 'Bracken Dawson'
        mock_db_get_count.return_value = 42
        mock_db_get_sector_a.return_value = 1
        mock_db_get_keyb_a.return_value = [1, 2, 3, 4, 5, 6]
        mock_db_get_secret_a.return_value = 'doesntmatter'
        mock_db_get_sector_b.return_value = 2
        mock_db_get_keyb_b.return_value = [2, 3, 4, 5, 6, 7]
        mock_db_get_secret_b.return_value = 'dontcare'
        mock_read_sector.return_value = 'irrelevant'
        mock_validate_sector.side_effect = [41, 42, 43]
        mock_write_sector.return_value = None
        mock_db_set_count.return_value = None
        mock_db_get_roles.side_effect = doord.EntryDatabaseException('wat roles?')
        assert self.tag.authenticate() == (True, [])
        mock_write_sector.assert_called_once_with(1, [1, 2, 3, 4, 5, 6], self.nfc.PICC_AUTHENT1B, 'doesntmatter', 43)

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.set_tag_user')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.set_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.set_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.set_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.set_tag_sector_b_secret')
    @mock.patch('doord.EntryDatabase.set_tag_sector_a_key_a')
    @mock.patch('doord.EntryDatabase.set_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.set_tag_sector_b_key_a')
    @mock.patch('doord.EntryDatabase.set_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.server_push_now')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    def test_initialize(self,
                        mock_db_server_push,
                        mock_db_keyb_b,
                        mock_db_keyb_a,
                        mock_db_keya_b,
                        mock_db_keya_a,
                        mock_db_secret_b,
                        mock_db_secret_a,
                        mock_db_sector_b,
                        mock_db_sector_a,
                        mock_db_count,
                        mock_db_user,
                        mock_db_init,
                        mock_configure_sector,
                        mock_validate_sector,
                        mock_read_sector,
                        mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = 'irrelephant'
        mock_validate_sector.side_effect = [0, 1, 0, 1]
        mock_configure_sector.return_value = None
        mock_db_keyb_b.return_value = None
        mock_db_keyb_a.return_value = None
        mock_db_keya_b.return_value = None
        mock_db_keya_a.return_value = None
        mock_db_secret_b.return_value = None
        mock_db_secret_a.return_value = None
        mock_db_sector_b.return_value = None
        mock_db_sector_a.return_value = None
        mock_db_count.return_value = None
        mock_db_user.return_value = None
        mock_db_server_push.return_value = None
        self.tag.initialize(3, 4, sector_keys="production")
        assert mock_write_sector.call_count == 2
        name, args, posargs = mock_write_sector.mock_calls[0]
        assert args[0] == 3
        assert args[1] == [255, 255, 255, 255, 255, 255]
        assert args[2] == self.nfc.PICC_AUTHENT1A
        assert args[4] == 0
        name, args, posargs = mock_write_sector.mock_calls[1]
        assert args[0] == 4
        assert args[1] == [255, 255, 255, 255, 255, 255]
        assert args[2] == self.nfc.PICC_AUTHENT1A
        assert args[4] == 1
        assert mock_configure_sector.call_count == 2
        name, args, posargs = mock_configure_sector.mock_calls[0]
        assert args[0] == 3
        assert args[1] == [255, 255, 255, 255, 255, 255]
        assert args[2] == self.nfc.PICC_AUTHENT1A
        assert args[4] == [0x7F, 0x07, 0x88, 0x69]
        name, args, posargs = mock_configure_sector.mock_calls[1]
        assert args[0] == 4
        assert args[1] == [255, 255, 255, 255, 255, 255]
        assert args[2] == self.nfc.PICC_AUTHENT1A
        assert args[4] == [0x7F, 0x07, 0x88, 0x69]
        assert mock_db_keyb_b.called
        assert mock_db_keyb_a.called
        assert mock_db_keya_b.called
        assert mock_db_keya_a.called
        assert mock_db_secret_b.called
        assert mock_db_secret_a.called
        mock_db_sector_a.assert_called_with('fedcba98', 3)
        mock_db_sector_b.assert_called_with('fedcba98', 4)
        mock_db_count.assert_called_with('fedcba98', 1)
        mock_db_user.assert_called_with('fedcba98', None)
        assert mock_db_server_push.called

    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    def test_initializei_already_in_db(self, mock_tag_in_db, mock_db_init):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = True
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except doord.TagException:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.__init__')
    @mock.patch('doord.EntryDatabase.set_tag_user')
    @mock.patch('doord.EntryDatabase.set_tag_count')
    @mock.patch('doord.EntryDatabase.set_tag_sector_a_sector')
    @mock.patch('doord.EntryDatabase.set_tag_sector_b_sector')
    @mock.patch('doord.EntryDatabase.set_tag_sector_a_secret')
    @mock.patch('doord.EntryDatabase.set_tag_sector_b_secret')
    @mock.patch('doord.EntryDatabase.set_tag_sector_a_key_a')
    @mock.patch('doord.EntryDatabase.set_tag_sector_a_key_b')
    @mock.patch('doord.EntryDatabase.set_tag_sector_b_key_a')
    @mock.patch('doord.EntryDatabase.set_tag_sector_b_key_b')
    @mock.patch('doord.EntryDatabase.server_push_now')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    def test_initialize(self,
                        mock_tag_in_db,
                        mock_db_server_push,
                        mock_db_keyb_b,
                        mock_db_keyb_a,
                        mock_db_keya_b,
                        mock_db_keya_a,
                        mock_db_secret_b,
                        mock_db_secret_a,
                        mock_db_sector_b,
                        mock_db_sector_a,
                        mock_db_count,
                        mock_db_user,
                        mock_db_init,
                        mock_configure_sector,
                        mock_validate_sector,
                        mock_read_sector,
                        mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = 'irrelephant'
        mock_validate_sector.side_effect = [0, 1, 0, 1]
        mock_configure_sector.return_value = None
        mock_db_keyb_b.return_value = None
        mock_db_keyb_a.return_value = None
        mock_db_keya_b.return_value = None
        mock_db_keya_a.return_value = None
        mock_db_secret_b.return_value = None
        mock_db_secret_a.return_value = None
        mock_db_sector_b.return_value = None
        mock_db_sector_a.return_value = None
        mock_db_count.return_value = None
        mock_db_user.return_value = None
        mock_db_server_push.return_value = None
        self.tag.initialize(3, 4, sector_keys="production")
        assert mock_write_sector.call_count == 2
        name, args, posargs = mock_write_sector.mock_calls[0]
        assert args[0] == 3
        assert args[1] == [255, 255, 255, 255, 255, 255]
        assert args[2] == self.nfc.PICC_AUTHENT1A
        assert args[4] == 0
        name, args, posargs = mock_write_sector.mock_calls[1]
        assert args[0] == 4
        assert args[1] == [255, 255, 255, 255, 255, 255]
        assert args[2] == self.nfc.PICC_AUTHENT1A
        assert args[4] == 1
        assert mock_configure_sector.call_count == 2
        name, args, posargs = mock_configure_sector.mock_calls[0]
        assert args[0] == 3
        assert args[1] == [255, 255, 255, 255, 255, 255]
        assert args[2] == self.nfc.PICC_AUTHENT1A
        assert args[4] == [0x7F, 0x07, 0x88, 0x69]
        name, args, posargs = mock_configure_sector.mock_calls[1]
        assert args[0] == 4
        assert args[1] == [255, 255, 255, 255, 255, 255]
        assert args[2] == self.nfc.PICC_AUTHENT1A
        assert args[4] == [0x7F, 0x07, 0x88, 0x69]
        assert mock_db_keyb_b.called
        assert mock_db_keyb_a.called
        assert mock_db_keya_b.called
        assert mock_db_keya_a.called
        assert mock_db_secret_b.called
        assert mock_db_secret_a.called
        mock_db_sector_a.assert_called_with('fedcba98', 3)
        mock_db_sector_b.assert_called_with('fedcba98', 4)
        mock_db_count.assert_called_with('fedcba98', 1)
        mock_db_user.assert_called_with('fedcba98', None)
        assert mock_db_server_push.called

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_write_fail_a(self,
                                     mock_db_init,
                                     mock_tag_in_db,
                                     mock_configure_sector,
                                     mock_validate_sector,
                                     mock_read_sector,
                                     mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.side_effect = doord.TagException('boom')
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except doord.TagException:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_write_fail_b(self,
                                     mock_db_init,
                                     mock_tag_in_db,
                                     mock_configure_sector,
                                     mock_validate_sector,
                                     mock_read_sector,
                                     mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.side_effect = [None, doord.TagException('boom')]
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except doord.TagException:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_read_fail_a(self,
                                    mock_db_init,
                                    mock_tag_in_db,
                                    mock_configure_sector,
                                    mock_validate_sector,
                                    mock_read_sector,
                                    mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = doord.TagException('shake')
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except doord.TagException:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_read_fail_b(self,
                                    mock_db_init,
                                    mock_tag_in_db,
                                    mock_configure_sector,
                                    mock_validate_sector,
                                    mock_read_sector,
                                    mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = ['not related to elephants', doord.TagException('the')]
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except doord.TagException:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_validate_fail_a(self,
                                        mock_db_init,
                                        mock_tag_in_db,
                                        mock_configure_sector,
                                        mock_validate_sector,
                                        mock_read_sector,
                                        mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = 'irrelephant'
        mock_validate_sector.side_effect = doord.TagException('room')
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_validate_fail_b(self,
                                        mock_db_init,
                                        mock_tag_in_db,
                                        mock_configure_sector,
                                        mock_validate_sector,
                                        mock_read_sector,
                                        mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = 'irrelephant'
        mock_validate_sector.side_effect = [0, doord.TagException('room')]
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_configure_fail_a(self,
                                         mock_db_init,
                                         mock_tag_in_db,
                                         mock_configure_sector,
                                         mock_validate_sector,
                                         mock_read_sector,
                                         mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = 'irrelephant'
        mock_validate_sector.side_effect = [0, 1]
        mock_configure_sector.return_value = doord.TagException('cant configure the unconfigurable')
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_configure_fail_b(self,
                                         mock_db_init,
                                         mock_tag_in_db,
                                         mock_configure_sector,
                                         mock_validate_sector,
                                         mock_read_sector,
                                         mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = 'irrelephant'
        mock_validate_sector.side_effect = [0, 1]
        mock_configure_sector.side_effect = [None, doord.TagException('like a cisco switch')]
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_reread_fail_a(self,
                                      mock_db_init,
                                      mock_tag_in_db,
                                      mock_configure_sector,
                                      mock_validate_sector,
                                      mock_read_sector,
                                      mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.side_effect = ['a', 'b', doord.TagException('like a fat gazelle')]
        mock_validate_sector.side_effect = [0, 1]
        mock_configure_sector.return_value = None
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_reread_fail_b(self,
                                      mock_db_init,
                                      mock_tag_in_db,
                                      mock_configure_sector,
                                      mock_validate_sector,
                                      mock_read_sector,
                                      mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.side_effect = ['a', 'b', 'c', doord.TagException('like a fat gazelle')]
        mock_validate_sector.side_effect = [0, 1]
        mock_configure_sector.return_value = None
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_revalidate_fail_a(self,
                                          mock_db_init,
                                          mock_tag_in_db,
                                          mock_configure_sector,
                                          mock_validate_sector,
                                          mock_read_sector,
                                          mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = 'Its after midnight now'
        mock_validate_sector.side_effect = [0, 1, doord.TagException('phail')]
        mock_configure_sector.return_value = None
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except:
            pass

    @mock.patch('doord.Tag.write_sector')
    @mock.patch('doord.Tag.read_sector')
    @mock.patch('doord.Tag.validate_sector')
    @mock.patch('doord.Tag.configure_sector')
    @mock.patch('doord.EntryDatabase.tag_in_db')
    @mock.patch('doord.EntryDatabase.__init__')
    def test_initialize_revalidate_fail_b(self,
                                          mock_db_init,
                                          mock_tag_in_db,
                                          mock_configure_sector,
                                          mock_validate_sector,
                                          mock_read_sector,
                                          mock_write_sector):
        mock_db_init.return_value = None
        self.tag.db = doord.EntryDatabase('https://example.com/rfid', 'lol')
        mock_tag_in_db.return_value = False
        mock_write_sector.return_value = None
        mock_read_sector.return_value = 'Its after midnight now'
        mock_validate_sector.side_effect = [0, 1, 0, doord.TagException('phail')]
        mock_configure_sector.return_value = None
        try:
            self.tag.initialize(3, 4, sector_keys="production")
            assert False
        except:
            pass


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
        assert self.tag.greater_than(1, 0) is True
        assert self.tag.greater_than(0, 1) is False
        assert self.tag.greater_than(0, 56635) is True
        assert self.tag.greater_than(65535, 0) is False
        assert self.tag.greater_than(32767, 0) is True
        assert self.tag.greater_than(32768, 0) is False
        assert self.tag.greater_than(0, 32768) is True
        assert self.tag.greater_than(0, 32767) is False

    def test_less_than(self):
        assert self.tag.less_than(1, 0) is False
        assert self.tag.less_than(0, 1) is True
        assert self.tag.less_than(0, 56635) is False
        assert self.tag.less_than(65535, 0) is True
        assert self.tag.less_than(32767, 0) is False
        assert self.tag.less_than(32768, 0) is True
        assert self.tag.less_than(0, 32768) is False
        assert self.tag.less_than(0, 32767) is True

    def test_encode_bcrypt64(self):
        assert self.tag.encode_bcrypt64('EAFsows8RLtDDZwP3wYfBuUMMeWL6lSp2kswfRuzNSavepq7uAZ.m') == [
            134, 112, 184, 170, 236, 250, 83, 243, 22, 197, 38, 71, 185, 172, 133, 3, 108, 57, 14, 136,
            53, 252, 73, 173, 184, 233, 202, 225, 4, 215, 15, 197, 197, 224, 202, 246, 176, 176, 1, 40]

    def test_unencode_bcrypt64(self):
        assert self.tag.unencode_bcrypt64([
            134, 112, 184, 170, 236, 250, 83, 243, 22, 197, 38, 71, 185, 172, 133, 3, 108, 57, 14, 136,
            53, 252, 73, 173, 184, 233, 202, 225, 4, 215, 15, 197, 197, 224, 202, 246, 176, 176, 1, 40]) == \
            'EAFsows8RLtDDZwP3wYfBuUMMeWL6lSp2kswfRuzNSavepq7uAZ.m'


class TestEntryDatabaseStatic(unittest.TestCase):

    @mock.patch('doord.EntryDatabase.__init__')
    def setUp(self, mock_db_init):
        mock_db_init.return_value = None
        self.db = doord.EntryDatabase('https://example.com/rfid', 'lol')

    def test_vivify(self):
        testdict = {
            'key_a': {
                'key_aa': 1,
                'key_ab': 'must not squash'
            },
            'key_b': 'also must not squash'
        }
        self.db.vivify(testdict, ['key_a', 'key_aa'], 2)
        self.db.vivify(testdict, ['key_a', 'key_ac'], 3)
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
        self.db = doord.EntryDatabase('https://example.com/rfid', 'lol')

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
        # This also tests a changing db on the server
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
        # This also tests a changing db on the server
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
        self.db.proc = multiprocessing.Process(target=self.db._server_poll_worker)
        mock_proc_start.return_value = None
        mock_proc_alive.return_value = False
        with mock.patch.object(multiprocessing.Process, '__init__', return_value=None) as mock_proc_init:
            self.db.server_poll()
        assert mock_proc_start.called

    @mock.patch('multiprocessing.Process.start')
    @mock.patch('multiprocessing.Process.is_alive')
    def test_server_poll_launcher_already_running(self, mock_proc_alive, mock_proc_start):
        self.db.proc = multiprocessing.Process(target=self.db._server_poll_worker)
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

    def test_tag_count_range(self):
        self.db.set_tag_count('fedcba98', -1)
        try:
            assert self.db.get_tag_count('fedcba98')
            assert False
        except doord.EntryDatabaseException:
            pass
        self.db.set_tag_count('fedcba98', 65536)
        try:
            assert self.db.get_tag_count('fedcba98')
            assert False
        except doord.EntryDatabaseException:
            pass

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
        self.db.set_tag_sector_a_key_a('fedcba98', [1, 2, 3, 4, 5, 6])
        assert self.db.get_tag_sector_a_key_a('fedcba98') == [1, 2, 3, 4, 5, 6]
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_a_key_b(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_a_key_b('fedcba98', [1, 2, 3, 4, 5, 7])
        assert self.db.get_tag_sector_a_key_b('fedcba98') == [1, 2, 3, 4, 5, 7]
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_b_key_a(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_b_key_a('fedcba98', [1, 2, 3, 4, 5, 8])
        assert self.db.get_tag_sector_b_key_a('fedcba98') == [1, 2, 3, 4, 5, 8]
        assert type(self.db.local) == multiprocessing.managers.DictProxy
        assert type(self.db.unsent) == multiprocessing.managers.DictProxy
        assert len(self.db.unsent.keys()) > 0

    def test_tag_sector_b_key_b(self):
        assert len(self.db.unsent.keys()) == 0
        self.db.set_tag_sector_b_key_b('fedcba98', [1, 2, 3, 4, 5, 9])
        assert self.db.get_tag_sector_b_key_b('fedcba98') == [1, 2, 3, 4, 5, 9]
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
        self.db.set_tag_sector_b_secret('fedcba98', base64.b64decode('0sS8ir/1YB8P47dwDRQZLFODh0HyrNg='))  # 23-bytes of random
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

    def test_tag_in_db(self):
        assert self.db.tag_in_db('fedcba98') is False
        self.db.local.update({'tags': {'fedcba98': {'assigned_user': '00001'}}})
        assert self.db.tag_in_db('fedcba98') is True
        assert self.db.tag_in_db('76543210') is False


class TestCodeFormat(unittest.TestCase):

    def test_pep8_conformance(self):
        pep8style = pep8.StyleGuide(quiet=False, config_file='tox.ini')
        result = pep8style.check_files([
            'doord.py',
            'test/unit/test_doord.py',
            'test/unit/mock_MFRC522.py'])
        self.assertEqual(result.total_errors, 0, "Found code style errors (and warnings).")

if __name__ == '__main__':
    unittest.main()
