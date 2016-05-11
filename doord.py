#!/usr/bin/env python2

import sys
import os
import syslog
import json
import base64
import time
from math import ceil
from multiprocessing import Process, Manager, Lock
import crc16
import bcrypt
import requests
import RPi.GPIO as gpio
sys.path.append("MFRC522-python")
import MFRC522


class DoorService:
    SERVER_POLL = 300  # seconds
    DOOR_IO = 15  # pi numbering
    SWITCH_IO = 11
    LED_IO = 18
    LED_HEARTBEAT_TIMES = (0.1, 5)  # on, off time in seconds
    LED_DOOR_OPEN_TIMES = (0.25, 0.25)
    LED_MAGIC_TAG_TIMES = (0.1, 0.1)
    MAGIC_TAG_TIMEOUT = 10  # seconds
    DEFAULT_SECTOR_A = 1
    DEFAULT_SECTOR_B = 2

    def __init__(self):

        try:
            rcfile = open('doorrc', 'r')
        except IOError:
            print "Can't read file: 'doorrc', you need that."
            sys.exit(1)
        self.settings = json.loads(rcfile.read())
        rcfile.close()

        self.DOOR_OPEN_TIME = 5  # seconds
        self.MAGIC_TAGS = {self.settings['init_tag_id']: "init_tag",  # 4-byte UIDs of "magic" tags that cause the doord to perform actions
                           "b": "init_tag_safe",  # NEVER set this one
                           self.settings['pull_db_tag_id']: "pull_db"}

        self.nfc = MFRC522.MFRC522()
        self.db = EntryDatabase(self.settings['server_url'], self.settings['api_key'])
        iself.MEMBER = self.settings['member_role_id']
        self.KEYHOLDER = self.settings['keyholder_role_id']
        self.LOCATION = self.settings['location_name']

        self.recent_tags = {}
        self.last_server_poll = os.times()[4]  # EntryDatabase will force a blocking poll when instantiated
        self.door_opened = os.times()[4]
        self.led_last_time = os.times()[4]

        gpio.setmode(gpio.BOARD)
        gpio.setup(self.DOOR_IO, gpio.OUT)
        gpio.output(self.DOOR_IO, gpio.LOW)
        gpio.setup(self.LED_IO, gpio.OUT)
        gpio.output(self.LED_IO, gpio.LOW)
        gpio.setup(SWITCH_IO, gpio.IN, pull_up_down=gpio.PUD_UP)

        print "Initialised"

    def __del__(self):
        gpio.cleanup()
        del self.nfc
        del self.db

    def main(self):
        while True:
            (status, TagType) = self.nfc.MFRC522_Request(self.nfc.PICC_REQIDL)  # searches for a card for up to approxamately 100ms

            # is a device presented
            if status == self.nfc.MI_OK:

                # run anti-collision and let the next id fall out
                (status, uid) = self.nfc.MFRC522_Anticoll()
                if status == self.nfc.MI_OK:
                    tag = Tag(uid, self.nfc, self.db)
                    if (str(tag)) in self.MAGIC_TAGS:
                        self.magic_tag(self.MAGIC_TAGS[str(tag)])
                        continue

                    if str(tag) in self.recent_tags:
                        if self.recent_tags[str(tag)] + self.DOOR_OPEN_TIME > os.times()[4]:
                            del tag
                            continue  # ignore a tag for DEBOUNCE seconds after sucessful auth
                    gpio.output(self.LED_IO, gpio.HIGH)
                    print "Found tag UID: " + str(tag)

                    # authenticate
                    # lock database first to keep updates whole
                    self.db.lock.acquire()
                    (status, roles) = tag.authenticate()
                    if status:
                        self.recent_tags[str(tag)] = os.times()[4]
                        if (self.KEYHOLDER in roles) or (self.MEMBER in roles and gpio.input(self.SWITCH_IO) == 0):
                            # open the door
                            print "Tag " + str(tag) + " authenticated"
                            tag.log_auth(self.LOCATION, "allowed")
                            self.door_opened = os.times()[4]
                            gpio.output(self.DOOR_IO, gpio.HIGH)
                        else:
                            print "Tag " + str(tag) + " authenticated but NOT keyholder"
                            tag.log_auth(self.LOCATION, "denied")
                        # update the server with tag counts and scans early
                        self.db.server_poll()
                        self.last_server_poll = os.times()[4]

                    else:
                        print "Tag " + str(tag) + " NOT authenticated"
                    self.db.lock.release()

                    del tag
                    gpio.output(self.LED_IO, gpio.LOW)
                    self.led_last_time = os.times()[4]

                else:
                    print "Failed to read UID"

            if self.door_opened > 0 and os.times()[4] > self.door_opened + self.DOOR_OPEN_TIME:
                # close the door
                gpio.output(self.DOOR_IO, gpio.LOW)
                self.door_opened = 0

            if os.times()[4] > self.last_server_poll + self.SERVER_POLL:
                self.db.server_poll()
                self.last_server_poll = os.times()[4]

            if gpio.input(self.DOOR_IO):
                # door open
                (ledon, ledoff) = self.LED_DOOR_OPEN_TIMES
            else:
                (ledon, ledoff) = self.LED_HEARTBEAT_TIMES
            if gpio.input(self.LED_IO):
                # LED on
                if os.times()[4] > self.led_last_time + ledon:
                    gpio.output(self.LED_IO, gpio.LOW)
                    self.led_last_time = os.times()[4]
            else:
                # LED off
                if os.times()[4] > self.led_last_time + ledoff:
                    gpio.output(self.LED_IO, gpio.HIGH)
                    self.led_last_time = os.times()[4]

    def magic_tag(self, function):
        if function is "init_tag":
            self.init_tag()
        elif function is "init_tag_safe":
            self.init_tag(sector_keys="safe")
        elif function is "pull_db":
            self.db.server_poll()
            self.last_server_poll = os.times()[4]

    def init_tag(self, sector_keys="production"):
        print "Entered tag init mode: " + str(sector_keys)
        magic_tag_start = os.times()[4]

        # get a tag
        while True:
            (status, TagType) = self.nfc.MFRC522_Request(self.nfc.PICC_REQIDL)

            # is a device presented
            if status == self.nfc.MI_OK:

                # run anti-collision and let the next id fall out
                (status, uid) = self.nfc.MFRC522_Anticoll()
                if status == self.nfc.MI_OK:
                    tag = Tag(uid, self.nfc, self.db)

                    # is it the magic tag still?
                    if str(tag) in self.MAGIC_TAGS:
                        del tag
                        continue

                    print "Found tag: " + str(tag)
                    gpio.output(self.LED_IO, gpio.HIGH)
                    self.db.lock.acquire()
                    try:
                        if sector_keys is "production":
                            tag.initialize(self.DEFAULT_SECTOR_A, self.DEFAULT_SECTOR_B)
                        else:
                            tag.initialize(self.DEFAULT_SECTOR_A, self.DEFAULT_SECTOR_B, sector_keys="safe")
                    except Exception as e:
                        print "Problem initializing tag: " + str(e)

                    self.db.lock.release()
                    gpio.output(self.LED_IO, gpio.LOW)
                    self.led_last_time = os.times()[4]
                    del tag
                    return

            # led blinking while waiting for a tag
            (ledon, ledoff) = self.LED_MAGIC_TAG_TIMES
            if gpio.input(self.LED_IO):
                # LED on
                if os.times()[4] > self.led_last_time + ledon:
                    gpio.output(self.LED_IO, gpio.LOW)
                    self.led_last_time = os.times()[4]
            else:
                # LED off
                if os.times()[4] > self.led_last_time + ledoff:
                    gpio.output(self.LED_IO, gpio.HIGH)
                    self.led_last_time = os.times()[4]

            # magic tag timeout
            if os.times()[4] > magic_tag_start + self.MAGIC_TAG_TIMEOUT:
                gpio.output(self.LED_IO, gpio.LOW)
                self.led_last_time = os.times()[4]
                return


class Tag:
    BCRYPT_BASE64_DICT = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    BCRYPT_VERSION = ['2', '2a', '2b', '2y']
    BCRYPT_COST = 8  # tuned for performance, we must hash 4 times per authentication, this could be reduced to 3 if needed
    SECTOR_LOCK_BYTES = [0x7F, 0x07, 0x88, 0x69]  # key a r/w, key b r/w/conf
    DEFAULT_KEY = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]  # the key locking un-written cards
    SAFE_A_KEY = [0x6B, 0x65, 0x79, 0x20, 0x61, 0x00]  # safe keys used for testing "key a" in ascii
    SAFE_B_KEY = [0x6B, 0x65, 0x79, 0x20, 0x62, 0x00]                             # "key b"

    # create tag object representing one session with one tag
    def __init__(self, uid, nfc, db):
        self.count = None  # the correct count
        self.count_a = None  # counts read from tag
        self.count_b = None
        self.uid = uid
        self.nfc = nfc
        self.db = db

        self.select()

    def select(self):
        self.nfc.MFRC522_SelectTag(self.uid)

    def unselect(self):
        self.nfc.MFRC522_StopCrypto1()

    def __del__(self):
        self.unselect()

    # attempt the whole authentication process with this tag
    def authenticate(self, location="default"):
        sector_a_ok = True
        sector_b_ok = True

        try:
            userid = self.db.get_tag_user(str(self))
        except EntryDatabaseException as e:
            if str(e) == "Unkown tag":
                print "Tag " + str(self) + " is alien"
            elif str(e) == "Unassigned tag":
                print "Tag " + str(self) + " is not assigned to anyone"
            else:
                print "Database error, could not load user id for tag: " + str(e)
            return (False, [])

        try:
            username = self.db.get_user_name(userid)
        except EntryDatabaseException as e:
            print "Database error, could not load user name: " + str(e)
            return (False, [])
        print "Tag is assigned to user " + userid + " (" + username + ")"

        try:
            self.count = self.db.get_tag_count(str(self))
        except EntryDatabaseException as e:
            print "Database error, could not load tag count: " + str(e)
            return (False, [])

        try:
            sector_a_data = self.read_sector(self.db.get_tag_sector_a_sector(str(self)),
                                             self.db.get_tag_sector_a_key_b(str(self)),
                                             self.nfc.PICC_AUTHENT1B)

            sector_b_data = self.read_sector(self.db.get_tag_sector_b_sector(str(self)),
                                             self.db.get_tag_sector_b_key_b(str(self)),
                                             self.nfc.PICC_AUTHENT1B)
        except TagException as e:
            print "Failed to Read sector: " + str(e)
            return (False, [])
        except EntryDatabaseException as e:
            print "Database error: " + str(e)
            return (False, [])

        try:
            self.count_a = self.validate_sector(sector_a_data,
                                                self.db.get_tag_sector_a_secret(str(self)))
        except TagException as e:
            print "Failed to validate sector a: " + str(e)
            sector_a_ok = False
        except EntryDatabaseException as e:
            print "Database error: " + str(e)
            return (False, [])
        try:
            self.count_b = self.validate_sector(sector_b_data,
                                                self.db.get_tag_sector_b_secret(str(self)))
        except TagException as e:
            print "Failed to validate sector b: " + str(e)
            sector_b_ok = False
        except EntryDatabaseException as e:
            print "Database error: " + str(e)
            return (False, [])

        if (sector_a_ok is False) and (sector_b_ok is False):
            print "Failed to authenticate, both sectors invalid"
            return (False, [])

        if sector_a_ok and sector_b_ok and 1 < self.subtract(self.count_a, self.count_b) < 65535:  # subtract() wraps in 16-bit positive space, -1 is 65535
            print "Warning: valid sector counts spaced higher than expected: A: " + str(self.count_a) + " B: " + str(self.count_b)
        if sector_a_ok and sector_b_ok and (self.count_a == self.count_b):
            print "Warning: valid sector counts spaced lower than expected: A: " + str(self.count_a) + " B: " + str(self.count_b)

        if (not sector_b_ok) or (sector_a_ok and self.greater_than(self.count_a, self.count_b)):
            if self.less_than(self.count_a, self.count):
                print "Duplicate tag detected, expected count: " + str(self.count) + ", tag count: " + str(self.count_a)
                return (False, [])
            if self.greater_than(self.count_a, self.count):
                print "Tag ahead of expected count, expected: " + str(self.count) + ", tag count: " + str(self.count_a) + ", continueing"
            try:
                self.write_sector(self.db.get_tag_sector_b_sector(str(self)),
                                  self.db.get_tag_sector_b_key_b(str(self)),
                                  self.nfc.PICC_AUTHENT1B,
                                  self.db.get_tag_sector_b_secret(str(self)),
                                  self.plus(self.count_a, 1))
                sector_b_backdata = self.read_sector(self.db.get_tag_sector_b_sector(str(self)),
                                                     self.db.get_tag_sector_b_key_b(str(self)),
                                                     self.nfc.PICC_AUTHENT1B)
                readback = self.validate_sector(sector_b_backdata,
                                                self.db.get_tag_sector_b_secret(str(self)))
            except TagException as e:
                print "Failed to update tag: " + str(e)
                return (False, [])
            except EntryDatabaseException as e:
                print "Database error: " + str(e)
                return (False, [])

            if readback != (self.plus(self.count_a, 1)):
                print "Tag readback not correct, expected: " + str(self.plus(self.count_a, 1)) + " Got: " + str(readback)
                return (False, [])

            self.db.set_tag_count(str(self), self.plus(self.count_a, 1))  # NEVER sucessfully authenticate without updating the count
        else:
            if self.less_than(self.count_b, self.count):
                print "Duplicate tag detected, expected count: " + str(self.count) + ", tag count: " + str(self.count_b)
                return (False, [])
            if self.greater_than(self.count_b, self.count):
                print "Tag ahead of expected count, expected: " + str(self.count) + ", tag count: " + str(self.count_b) + ", continuing"

            try:
                self.write_sector(self.db.get_tag_sector_a_sector(str(self)),
                                  self.db.get_tag_sector_a_key_b(str(self)),
                                  self.nfc.PICC_AUTHENT1B,
                                  self.db.get_tag_sector_a_secret(str(self)),
                                  self.plus(self.count_b, 1))
                sector_a_backdata = self.read_sector(self.db.get_tag_sector_a_sector(str(self)),
                                                     self.db.get_tag_sector_a_key_b(str(self)),
                                                     self.nfc.PICC_AUTHENT1B)
                readback = self.validate_sector(sector_a_backdata,
                                                self.db.get_tag_sector_a_secret(str(self)))
            except TagException as e:
                print "Failed to update tag: " + str(e)
                return (False, [])
            except EntryDatabaseException as e:
                print "Database error: " + str(e)
                return (False, [])

            if readback != (self.plus(self.count_b, 1)):
                print "Tag readback not correct, expected: " + str(self.plus(self.count_b, 1)) + " Got: " + str(readback)
                return (False, [])

            self.db.set_tag_count(str(self), self.plus(self.count_b, 1))  # NEVER sucessfully authenticate without updating the count

        roles = []
        try:
            roles = self.db.get_user_roles(self.db.get_tag_user(str(self)))
        except EntryDatabaseException as e:
            print "failed to get user roles: " + str(e)

        return (True, roles)

    def log_auth(self, location, result):
        self.db.log_auth(str(self), location, result)

    def initialize(self, sector_a_sector, sector_b_sector, sector_keys="production"):
        if self.db.tag_in_db(str(self)):
            raise TagException('DO NOT initialise a serial that is in the database, DOS or Breach may result.')

        print "Generating random elements"
        # bcrypt will reject a count padded with a null (chr(0)) character.
        # It will also reject unicode text objects (u"hello") but not unicode
        # characters in a regular string (b"You can't have unicode in python comments")
        while True:
            sector_a_secret = os.urandom(23)  # 23 because this matches the entropy of the bcrypt digest itself
            if b"\x00" not in sector_a_secret:
                break
        while True:
            sector_b_secret = os.urandom(23)
            if b"\x00" not in sector_b_secret:
                break

        # Mifare keys however, may contain zeros
        if sector_keys == "production":
            sector_a_key_a = map(ord, os.urandom(6))
            sector_a_key_b = map(ord, os.urandom(6))
            sector_b_key_a = map(ord, os.urandom(6))
            sector_b_key_b = map(ord, os.urandom(6))
        else:
            print "WARNING: Using safe keys, this is NOT secure, please use production keys"
            sector_a_key_a = self.SAFE_A_KEY
            sector_a_key_b = self.SAFE_B_KEY
            sector_b_key_a = self.SAFE_A_KEY
            sector_b_key_b = self.SAFE_B_KEY

        # if this failes anywhere we should remember the sector keys used
        # so we can recover the tag
        try:
            print "Writing sector a: " + str(sector_a_sector)
            self.write_sector(sector_a_sector,
                              self.DEFAULT_KEY,
                              self.nfc.PICC_AUTHENT1A,
                              sector_a_secret,
                              0)
            print "Writing sector b: " + str(sector_b_sector)
            self.write_sector(sector_b_sector,
                              self.DEFAULT_KEY,
                              self.nfc.PICC_AUTHENT1A,
                              sector_b_secret,
                              1)
            print "Readback sectors"
            sector_a_backdata = self.read_sector(sector_a_sector,
                                                 self.DEFAULT_KEY,
                                                 self.nfc.PICC_AUTHENT1A)
            readback_a = self.validate_sector(sector_a_backdata,
                                              sector_a_secret)
            if readback_a != 0:
                raise TagException("Sector a: " + str(sector_a_sector) + ", readback count incorect")

            sector_b_backdata = self.read_sector(sector_b_sector,
                                                 self.DEFAULT_KEY,
                                                 self.nfc.PICC_AUTHENT1A)
            readback_b = self.validate_sector(sector_b_backdata,
                                              sector_b_secret)
            if readback_b != 1:
                raise TagException("Sector b: " + str(sector_b_sector) + ", readback count incorrect")

            print "Securing sectors"
            self.configure_sector(sector_a_sector,
                                  self.DEFAULT_KEY,
                                  self.nfc.PICC_AUTHENT1A,
                                  sector_a_key_a,
                                  self.SECTOR_LOCK_BYTES,
                                  sector_a_key_b)
            self.configure_sector(sector_b_sector,
                                  self.DEFAULT_KEY,
                                  self.nfc.PICC_AUTHENT1A,
                                  sector_b_key_a,
                                  self.SECTOR_LOCK_BYTES,
                                  sector_b_key_b)

            print "Readback sectors"
            sector_a_backdata = self.read_sector(sector_a_sector,
                                                 sector_a_key_b,
                                                 self.nfc.PICC_AUTHENT1B)
            readback_a = self.validate_sector(sector_a_backdata,
                                              sector_a_secret)
            if readback_a != 0:
                raise TagException("Sector a: " + str(sector_a_sector) + ", readback count incorect")

            sector_b_backdata = self.read_sector(sector_b_sector,
                                                 sector_b_key_b,
                                                 self.nfc.PICC_AUTHENT1B)
            readback_b = self.validate_sector(sector_b_backdata,
                                              sector_b_secret)
            if readback_b != 1:
                raise TagException("Sector b: " + str(sector_b_sector) + ", readback count incorrect")

            print "Sending tag details to server"
            self.db.set_tag_user(str(self), None)
            self.db.set_tag_count(str(self), 1)
            self.db.set_tag_sector_a_sector(str(self), sector_a_sector)
            self.db.set_tag_sector_b_sector(str(self), sector_b_sector)
            self.db.set_tag_sector_a_secret(str(self), sector_a_secret)
            self.db.set_tag_sector_b_secret(str(self), sector_b_secret)
            self.db.set_tag_sector_a_key_a(str(self), sector_a_key_a)
            self.db.set_tag_sector_a_key_b(str(self), sector_a_key_b)
            self.db.set_tag_sector_b_key_a(str(self), sector_b_key_a)
            self.db.set_tag_sector_b_key_b(str(self), sector_b_key_b)
            self.db.server_push_now()
        except Exception as e:
            print "sector a (" + str(sector_a_sector) + "):"
            print "  key a: " + str(sector_a_key_a)
            print "  key b: " + str(sector_a_key_b)
            print "sector b (" + str(sector_b_sector) + "):"
            print "  key a: " + str(sector_b_key_a)
            print "  key b: " + str(sector_b_key_b)
            print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
            print "FAILED TO WRITE TAG or UPDATE SERVER - WRITE DOWN THE KEYS SHOWN ABOVE AND STICK THEM TO THE TAG RIGHT NOW!!!!"
            print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
            # make doubly sure this gets logged
            syslog.syslog("doord: Failed to init a tag, keys attempted were: sector a (1): key a: " +
                          str(sector_a_key_a) + " key b: " + str(sector_a_key_b) + " sector b (2): key a: " +
                          str(sector_b_key_a) + "  key b: " + str(sector_b_key_b))
            raise

        print "Successfully initialized tag"

    # return a validated count stored in the sector data given or rasie exception
    def validate_sector(self, sector_data, secret):
        # Assert crc16 matches sector or log corrupt sector and return
        payload = "".join(map(chr, sector_data[0:46]))
        crc = (sector_data[46] << 8) + sector_data[47]
        if not crc16.crc16xmodem(payload) == crc:
            raise TagException("Sector data failed checksum")

        count = (sector_data[0] << 8) + sector_data[1]
        algorithm = sector_data[2]
        cost = sector_data[3]
        digest = self.unencode_bcrypt64(sector_data[4:44])
        reserved = sector_data[44:46]

        if algorithm > (len(self.BCRYPT_VERSION) - 1):
            raise TagException("Unknown bcrypt algorithm: " + str(algorithm))

        for b in reserved:
            if b != 0:
                raise TagException("Data in padding")

        read_hash = '$' + str(self.BCRYPT_VERSION[algorithm]) + '$' + str(cost).zfill(2) + '$' + digest

        try:
            calculated_hash = bcrypt.hashpw(str(count) + str(secret), read_hash)
        except ValueError as e:
            raise TagException('Failed to make hash to compare: ' + str(e))

        if calculated_hash != read_hash:
            raise TagException("Hash does not match, count is not authentic.")

        return count

    # return data stored "securely" in given sector
    def read_sector(self, sector, key, keyspec):
        status = self.nfc.Auth_Sector(keyspec, sector, key, self.uid)
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to authenticate sector " + str(sector) + " of Tag " + str(self))

        (status, data) = self.nfc.Read_Sector(sector)
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to read sector " + str(sector) + " of Tag " + str(self))

        return data

    def __str__(self):
        return format(self.uid[0], "x").zfill(2) + format(self.uid[1], "x").zfill(2) + format(self.uid[2], "x").zfill(2) + format(self.uid[3], "x").zfill(2)

    # write a sector to the tag given the count and secret
    def write_sector(self, sector, key, keyspec, secret, count):
        generated_hash = bcrypt.hashpw(str(count) + str(secret), bcrypt.gensalt(self.BCRYPT_COST))
        hash_parts = generated_hash.split("$")

        data = []
        data.append(count >> 8)
        data.append(count & 0xFF)
        data.append(self.BCRYPT_VERSION.index(hash_parts[1]))  # bcrypt algorithm
        data.append(int(hash_parts[2]))  # cost
        data.extend(self.encode_bcrypt64(hash_parts[3]))  # salt & digest
        data.extend([0, 0])  # padding
        crc = crc16.crc16xmodem("".join(map(chr, data)))  # crc
        data.append(crc >> 8)
        data.append(crc & 0xFF)

        status = self.nfc.Auth_Sector(keyspec, sector, key, self.uid)
        if status != self.nfc.MI_OK:
            raise TagException("Failed to authenticate sector " + str(sector) + " of Tag " + str(self))
        (status, backData) = self.nfc.Write_Block(sector * 4, data[0:16])
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to write sector " + str(sector) + " block " + str(sector * 4) + " of Tag " + str(self))
        (status, backData) = self.nfc.Write_Block(sector * 4 + 1, data[16:32])
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to write sector " + str(sector) + " block " + str(sector * 4 + 1) + " of Tag " + str(self))
        (status, backData) = self.nfc.Write_Block(sector * 4 + 2, data[32:48])
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to write sector " + str(sector) + " block " + str(sector * 4 + 2) + " of Tag " + str(self))

    def configure_sector(self, sector, key, keyspec, key_a, lock_bytes, key_b):
        status = self.nfc.Auth_Sector(keyspec, sector, key, self.uid)
        if status != self.nfc.MI_OK:
            raise TagException("Failed to authenticate sector " + str(sector) + " of Tag " + str(self))
        data = []
        data.extend(key_a)
        data.extend(lock_bytes)
        data.extend(key_b)
        (status, backData) = self.nfc.Write_Block(sector * 4 + 3, data)
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to write sector " + str(sector) + " block " + str(sector * 4 + 3) + " of Tag " + str(self))

    # convert from binary byte array to bcrypt base64
    def unencode_bcrypt64(self, binary_arr):
        base64 = ""
        i = 0
        binary = 0
        for c in binary_arr:
            binary = binary + (c << i)
            i += 8
        for i in range(int(len(binary_arr) * 8 / 6.0)):
            base64 = base64 + str(list(self.BCRYPT_BASE64_DICT)[(binary >> (i * 6)) & 63])
        return base64

    # convert from bcrypt base64 format to binary byte array
    def encode_bcrypt64(self, base64):
        binary_int = 0
        i = 0
        for c in list(base64):
            binary_int = binary_int + (self.BCRYPT_BASE64_DICT.index(c) << i)
            i += 6
        binary = []
        for i in range(int(ceil(len(list(base64)) * 6 / 8.0))):
            binary.append(int(((binary_int >> (i * 8)) & 0xff)))
        return binary

    # 16-bit wrapping plus function
    def plus(self, left, right):
        return (left + right) % (2**16)

    def subtract(self, left, right):
        return (left - right) % (2**16)

    # 16-bit wrapping greater than function
    def greater_than(self, left, right):
        left = (left + (2 ** 16 / 2)) % (2 ** 16)
        right = (right + (2 ** 16 / 2)) % (2 ** 16)
        if left == 0 and right == 65535:
            return True
        return left > right

    # 16-bit wrapping less than function
    def less_than(self, left, right):
        left = (left + (2 ** 16 / 2)) % (2 ** 16)
        right = (right + (2 ** 16 / 2)) % (2 ** 16)
        if left == 65535 and right == 0:
            return True
        return left < right


class TagException(Exception):
    pass


class EntryDatabase:

    def __init__(self, server_url, api_key):
        self.proc = None
        self.mgr = Manager()
        self.lock = Lock()
        self.local = self.mgr.dict()  # shared objects
        self.unsent = self.mgr.dict()  # updates we've never tried to send
        self.send_queue = self.mgr.list()  # list uf updates we're trying to send in order
        self.server_url = None
        self.api_key = None
        self.server_url = server_url
        self.api_key = api_key

        # pull server copy down, retry forever here as we can do nothing
        # until we have the db.
        connected = False
        while not connected:
            print "Connecting to " + self.server_url
            try:
                self.server_pull_now()
                connected = True
            except EntryDatabaseException as e:
                print "Error connecting to server: " + str(e)
                time.sleep(60)

    def __del__(self):
        if type(self.proc) is Process and self.proc.is_alive():
            self.proc.terminate()

    # blocking pull of db from server
    def server_pull_now(self):
        try:
            response = requests.get(self.server_url, cookies={'SECRET': self.api_key})
            if response.status_code == requests.codes.ok:
                self.local.clear()
                self.local.update(json.loads(response.text))
            else:
                raise EntryDatabaseException("Server returned bad status to GET: " + str(response.status_code) +
                                             " - " + str(response.text))
        except requests.exceptions.RequestException as e:
            raise EntryDatabaseException("GET request error: " + str(e))

    # blocking update of server
    def server_push_now(self):
        self.send_queue.append(dict(self.unsent))
        self.unsent.clear()

        try:
            while len(self.send_queue) > 0:
                response = requests.post(self.server_url,
                                         cookies={'SECRET': self.api_key},
                                         data=json.dumps(self.send_queue[0]),
                                         headers={'content-type': 'application/json'})
                if response.status_code == requests.codes.ok:
                    self.send_queue.pop(0)
                else:
                    raise EntryDatabaseException("Server returned bad status to POST:" + str(response.status_code) +
                                                 " - " + str(response.text) + " (send_queue: " +
                                                 str(len(self.send_queue)) + ")")
        except requests.exceptions.RequestException as e:
            raise EntryDatabaseException("POST request error: " + str(e)) + " (send_queue: " + \
                str(len(self.send_queue)) + ")"

    def _server_poll_worker(self):
        if len(self.unsent) > 0:
            # copy complete updates from unsent
            self.lock.acquire()
            self.send_queue.append(dict(self.unsent))
            self.unsent.clear()
            self.lock.release()

            # try to send all the updates in order
            try:
                while len(self.send_queue) > 0:
                    response = requests.post(self.server_url,
                                             cookies={'SECRET': self.api_key},
                                             data=json.dumps(self.send_queue[0]),
                                             headers={'content-type': 'application/json'})
                    if response.status_code == requests.codes.ok:
                        self.send_queue.pop(0)
                    else:
                        # there is nobody to catch anything thrown here
                        print "Server returned bad status to POST:" + str(response.status_code) + " (send_queue: " + str(len(self.send_queue)) + ")"
                        # do not pull if we fail to post, it may clobber unsent from local
                        # do not continue to push send_queue on a failure, it may deliver out of order
                        return
            except requests.exceptions.RequestException as e:
                print "POST request error: " + str(e) + " (send_queue: " + str(len(self.send_queue)) + ")"
                # same warnings as bad status code above
                return

        try:
            response = requests.get(self.server_url, cookies={'SECRET': self.api_key})
            if response.status_code == requests.codes.ok:
                self.lock.acquire()
                # avoid re-declaring local as dict, small chance of a tag being read as alien here then working
                # very soon after
                self.local.clear()
                self.local.update(json.loads(response.text))
                self.lock.release()
            else:
                print "Server returned bad status to GET: " + str(response.status_code)
        except requests.exceptions.RequestException as e:
            print "GET request error: " + str(e)

    # attempt to send unsent changes to the server and update the local copy, asynchronously
    def server_poll(self):
        if type(self.proc) is Process and self.proc.is_alive():
            print "Server poll still in progress, not starting another."
        else:
            self.proc = Process(target=self._server_poll_worker)
            self.proc.start()

    def get_tag_user(self, uid):
        try:
            if 'tags' not in self.local or uid not in self.local['tags']:
                raise EntryDatabaseException("Unkown tag")
            if 'assigned_user' not in self.local["tags"][uid] or self.local["tags"][uid]["assigned_user"] is None:
                raise EntryDatabaseException("Unassigned tag")
            if type(self.local['tags'][uid]['assigned_user']) in [str, unicode]:
                return self.local['tags'][uid]['assigned_user']
            else:
                raise EntryDatabaseException("Assigned user id not string: " + str(self.local['tags'][uid]['assigned_user']))
        except TypeError as e:
            raise EntryDatabaseException("TypeError: " + str(e))

    def set_tag_user(self, uid, user):
        p_local = dict(self.local)  # copy and cast the shared object to a real dict before vivifying it
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'assigned_user'], user)
        self.vivify(p_unsent, ['tags', uid, 'assigned_user'], user)
        self.local.update(p_local)  # update after to set the shared object to the content of the dict
        self.unsent.update(p_unsent)

    def get_tag_count(self, uid):
        try:
            if (type(self.local['tags'][uid]['count']) is int) and (0 <= self.local['tags'][uid]['count'] <= 65535):
                return self.local['tags'][uid]['count']
            else:
                raise EntryDatabaseException("count not an int or out of range: " + str(self.local['tags'][uid]['count']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def vivify(self, dic, keys, value):
        key = keys.pop(0)
        if key not in dic:
            if len(keys) < 1:
                dic[key] = value
            else:
                dic.update({key: {}})
                self.vivify(dic[key], keys, value)
        else:
            if len(keys) < 1:
                dic[key] = value
            else:
                self.vivify(dic[key], keys, value)

    def set_tag_count(self, uid, count):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'count'], count)
        self.vivify(p_unsent, ['tags', uid, 'count'], count)
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_a_sector(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_a_sector']) is int:
                return self.local['tags'][uid]['sector_a_sector']
            else:
                raise EntryDatabaseException("sector_a_sector not an int: " + str(self.local['tags'][uid]['sector_a_sector']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_a_sector(self, uid, sector):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'sector_a_sector'], sector)
        self.vivify(p_unsent, ['tags', uid, 'sector_a_sector'], sector)
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_b_sector(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_b_sector']) is int:
                return self.local['tags'][uid]['sector_b_sector']
            else:
                raise EntryDatabaseException("sector_b_sector not an int: " + str(self.local['tags'][uid]['sector_b_sector']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_b_sector(self, uid, sector):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'sector_b_sector'], sector)
        self.vivify(p_unsent, ['tags', uid, 'sector_b_sector'], sector)
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_a_key_a(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_a_key_a']) in [str, unicode]:
                key = map(ord, base64.b64decode(self.local['tags'][uid]['sector_a_key_a']))
                if len(key) == 6:
                    return key
                else:
                    raise EntryDatabaseException("sector_a_key_a is incorrect length: " + str(key))
            else:
                raise EntryDatabaseException("sector_a_key_a not a string: " + str(self.local['tags'][uid]['sector_a_key_a']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_a_key_a(self, uid, key):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'sector_a_key_a'], base64.b64encode("".join(map(chr, key))))
        self.vivify(p_unsent, ['tags', uid, 'sector_a_key_a'], base64.b64encode("".join(map(chr, key))))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_a_key_b(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_a_key_b']) in [str, unicode]:
                key = map(ord, base64.b64decode(self.local['tags'][uid]['sector_a_key_b']))
                if len(key) == 6:
                    return key
                else:
                    raise EntryDatabaseException("sector_a_key_b is incorrect length: " + str(key))
            else:
                raise EntryDatabaseException("sector_a_key_b not a string: " + str(self.local['tags'][uid]['sector_a_key_b']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_a_key_b(self, uid, key):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'sector_a_key_b'], base64.b64encode("".join(map(chr, key))))
        self.vivify(p_unsent, ['tags', uid, 'sector_a_key_b'], base64.b64encode("".join(map(chr, key))))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_b_key_a(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_b_key_a']) in [str, unicode]:
                key = map(ord, base64.b64decode(self.local['tags'][uid]['sector_b_key_a']))
                if len(key) == 6:
                    return key
                else:
                    raise EntryDatabaseException("sector_b_key_a is incorrect length: " + str(key))
            else:
                raise EntryDatabaseException("sector_b_key_a not a string: " + str(self.local['tags'][uid]['sector_b_key_a']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_b_key_a(self, uid, key):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'sector_b_key_a'], base64.b64encode("".join(map(chr, key))))
        self.vivify(p_unsent, ['tags', uid, 'sector_b_key_a'], base64.b64encode("".join(map(chr, key))))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_b_key_b(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_b_key_b']) in [str, unicode]:
                key = map(ord, base64.b64decode(self.local['tags'][uid]['sector_b_key_b']))
                if len(key) == 6:
                    return key
                else:
                    raise EntryDatabaseException("sector_b_key_b is incorrect length: " + str(key))
            else:
                raise EntryDatabaseException("sector_b_key_b not a string: " + str(self.local['tags'][uid]['sector_b_key_b']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_b_key_b(self, uid, key):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'sector_b_key_b'], base64.b64encode("".join(map(chr, key))))
        self.vivify(p_unsent, ['tags', uid, 'sector_b_key_b'], base64.b64encode("".join(map(chr, key))))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_a_secret(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_a_secret']) in [str, unicode]:
                return base64.b64decode(self.local['tags'][uid]['sector_a_secret'])
            else:
                raise EntryDatabaseException("sector_a_secret is not string: " + str(self.local['tags'][uid]['sector_a_secret']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_a_secret(self, uid, secret):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'sector_a_secret'], base64.b64encode(secret))
        self.vivify(p_unsent, ['tags', uid, 'sector_a_secret'], base64.b64encode(secret))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_b_secret(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_b_secret']) in [str, unicode]:
                return base64.b64decode(self.local['tags'][uid]['sector_b_secret'])
            else:
                raise EntryDatabaseException("sector_b_secret is not string: " + str(self.local['tags'][uid]['sector_b_secret']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_b_secret(self, uid, secret):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags', uid, 'sector_b_secret'], base64.b64encode(secret))
        self.vivify(p_unsent, ['tags', uid, 'sector_b_secret'], base64.b64encode(secret))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_user_name(self, userid):
        try:
            if type(self.local['users'][userid]['name']) in [str, unicode]:
                return self.local['users'][userid]['name']
            else:
                raise EntryDatabaseException("User name is not a string: " + str(self.local['users'][userid]['name']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def get_user_roles(self, userid):
        try:
            if type(self.local['users'][userid]['roles']) is list:
                return self.local['users'][userid]['roles']
            else:
                raise EntryDatabaseException("User roles is not a list: " + str(self.local['users'][userid]['roles']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def tag_in_db(self, uid):
        if 'tags' in self.local:
            return uid in self.local['tags']
        return False

    def log_auth(self, uid, location, result):
        # vivify cannot append to lists
        scans = []
        try:
            scans = self.unsent['tags'][uid]['scans']
        except KeyError:
            pass

        user = None
        try:
            user = self.get_tag_user(uid)
        except EntryDatabaseException:
            pass

        scans.append({"date": int(time.time()),
                      "location": location,
                      "result": result,
                      "assigned_user": user})

        # this does not need to be stored locally
        p_unsent = dict(self.unsent)
        self.vivify(p_unsent, ['tags', uid, 'scans'], scans)
        self.unsent.update(p_unsent)


class EntryDatabaseException(Exception):
    pass

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] != "safe" and sys.argv[1] != "init":
            print "python doord.py [init|safe [sector_a_sector] [sector_b_sector]|help]"
            print ""
            print "The door authentiction server, runs as a deamon with no arguments."
            print "Put the server url and api_key in the doorrc file."
            print "    init - Initialise a tag and add it to thre server."
            print "    safe - Initialise a tag with well known keys ('key a' and"
            print "           'key b', big endian ASCII encoded)."
            print "           Optionally include sectors of the tag to initialise."
            print "    help - Show this help document."
            sys.exit(2)

        try:
            rcfile = open('doorrc', 'r')
        except IOError:
            print "Can't read file: 'doorrc', you need that."
            sys.exit(1)
        settings = json.loads(rcfile.read())
        rcfile.close()

        self.nfc = MFRC522.MFRC522()
        self.db = EntryDatabase(self.settings['server_url'], self.settings['api_key'])
        nfc = MFRC522.MFRC522()
        db = EntryDatabase(settings['server_url'], settings['api_key'])
        if sys.argv[1] == "init":
            print "Initializing tag with production keys"
        else:
            print "Initializing tag with well known keys \"key a\" and \"key b\""
            print "WARNING: using well konnw keys is NOT secure, please use production keys."
        print "Present tag.."
        status = nfc.MI_NOTAGERR

        sector_a_sector = 1
        try:
            if type(sys.argv[2]) is int:
                sector_a_sector = sys.argv[2]
        except IndexError:
            pass
        sector_b_sector = 2
        try:
            if type(sys.argv[3]) is int:
                sector_b_sectpr = sys.argv[3]
        except IndexError:
            pass

        # wait for an nfc device to be presented
        while status != nfc.MI_OK:
            (status, TagType) = nfc.MFRC522_Request(nfc.PICC_REQIDL)
        print "NFC device presented"

        (status, uid) = nfc.MFRC522_Anticoll()
        if status == nfc.MI_OK:
            tag = Tag(uid, nfc, db)
            print "Found tag UID: " + str(tag)

            if sys.argv[1] == "init":
                tag.initialize(sector_a_sector, sector_b_sector)
            else:
                tag.initialize(sector_a_sector, sector_b_sector, sector_keys="safe")

            sys.exit(0)

    inst = DoorService()
    inst.main()
