import unittest
import mock
import sys
import os
import mock

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

if __name__ == '_main__':
    unittest.main()
