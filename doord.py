import sys, os, syslog, json, base64, time
from math import ceil
from multiprocessing import Process, Manager
import crc16, bcrypt, requests
sys.path.append("MFRC522-python")
import MFRC522

class DoorService:
    nfc = None
    db = None
    DEBOUNCE = 5 #seconds
    recent_tags = {}
    SERVER_POLL = 300 #seconds
    last_server_poll = os.times()[4] #EntryDatabase will force a blocking poll when instantiated
    DOOR_IO = 7 #pi numbering
    DOOR_OPEN_TIME = 5 #seconds
    door_opened = 0;
    FRIEND = 1
    TRUSTEE = 2
    SUPPORTER = 3
    MEMBER = 4
    KEYHOLDER = 5
    LOCATION = "DOOR1"

    def __init__(self):
        self.nfc = MFRC522.MFRC522()
        self.db = EntryDatabase()

        self.set_pi_pin_mode(self.DOOR_IO, 'out')
        self.write_pi_pin(self.DOOR_IO, 0)

        print "Initialised"

    def __del__(self):
        self.release_pi_pin(self.DOOR_IO)
        del self.nfc
        del self.db

    def main(self):
        while True:
            (status,TagType) = self.nfc.MFRC522_Request(self.nfc.PICC_REQIDL) #searches for a card for up to approxamately 100ms

            # is a device presented
            if status == self.nfc.MI_OK:

                # run anti-collision and let one id fall out #TODO work out how to select other tags for people presenting a whole wallet. We should get an array of UIDs.
                (status,uid) = self.nfc.MFRC522_Anticoll()
                if status == self.nfc.MI_OK:
                    tag = Tag(uid, self.nfc, self.db)
                    if self.recent_tags.has_key(str(tag)):
                        if self.recent_tags[str(tag)] + self.DEBOUNCE > os.times()[4]:
                            del tag
                            continue #ignore a tag for DEBOUNCE seconds after sucessful auth
                    print "Found tag UID: " + str(tag)

                    #authenticate
                    (status, roles) = tag.authenticate()
                    if status:
                        self.recent_tags[str(tag)] = os.times()[4]
                        if self.KEYHOLDER in roles:
                            #open the door
                            print "Tag " + str(tag) + " authenticated"
                            tag.log_auth(self.LOCATION, "allowed")
                            self.door_opened = os.times()[4]
                            self.write_pi_pin(self.DOOR_IO, 1)
                        else:
                            print "Tag " + str(tag) + " authenticated but NOT keyholder"
                            tag.log_auth(self.LOCATION, "denied")

                    else:
                        print "Tag " + str(tag) + " NOT authenticated"

                    del tag

                else:
                    print "Failed to read UID"

            if self.door_opened > 0 and os.times()[4] > self.door_opened + self.DOOR_OPEN_TIME:
                #close the door
                self.write_pi_pin(self.DOOR_IO, 0)
                self.door_opened = 0

            if os.times()[4] > self.last_server_poll + self.SERVER_POLL:
                self.db.server_poll()
                self.last_server_poll = os.times()[4]

    def set_pi_pin_mode(self, pin, mode):
        fexp = open('/sys/class/gpio/export', 'w')
        fexp.write(str(pin))
        try:
            fexp.close()
        except IOError:
            del fexp
        attempts = 0
        while True:
            attempts += 1
            try:
                fdir = open('/sys/class/gpio/gpio' + str(pin) + '/direction', 'w')
                fdir.write(mode)
                fdir.close()
                break
            except IOError:
                if attempts > 10:
                    raise
                time.sleep(0.1)

    def release_pi_pin(self, pin):
        fexp = open('/sys/class/gpio/unexport', 'w')
        fexp.write(str(pin))
        try:
            fexp.close()
        except IOError:
            del fexp

    def write_pi_pin(self, pin, val):
        fval = open('/sys/class/gpio/gpio' + str(pin) + '/value', 'w')
        fval.write(str(val))
        fval.close()

class Tag:
    uid = None
    nfc = None
    db = None
    count = None    #the correct count
    count_a = None  #counts read from tag
    count_b = None
    BCRYPT_BASE64_DICT = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    BCRYPT_VERSION = ['2', '2a', '2b', '2y']
    BCRYPT_COST = 8    #tuned for performance, we must hash 4 times per authentication, this could be reduced to 3 if needed
    SECTOR_LOCK_BYTES = [0x7F,0x07,0x88,0x69] #key a r/w, key b r/w/conf

    #create tag object representing one session with one tag
    def __init__(self, uid, nfc, db):
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

    #attempt the whole authentication process with this tag
    def authenticate(self, location="default"):
        sector_a_ok = True
        sector_b_ok = True

        try:
            userid = self.db.get_tag_user(str(self))
        except EntryDatabaseException as e:
            #TESTME
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
                                             self.nfc.PICC_AUTHENT1B) #TESTME test missinig fields

            sector_b_data = self.read_sector(self.db.get_tag_sector_b_sector(str(self)),
                                             self.db.get_tag_sector_b_key_b(str(self)),
                                             self.nfc.PICC_AUTHENT1B)
        except TagException as e:
            #TESTME one and both
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

        if (sector_a_ok == False) and (sector_b_ok == False):
            print "Failed to authenticate, both sectors invalid"
            return (False, [])

        if sector_a_ok and sector_b_ok and 1 < self.subtract(self.count_a, self.count_b) < 65535: #subtract() wraps in 16-bit positive space, -1 is 65535
            #TESTME
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
                #TESTME, maybe, it's hard
                print "Tag readback not correct, expected: " + str(self.plus(self.count_a, 1)) + " Got: " + str(readback)
                return (False, [])

            self.db.set_tag_count(str(self), self.plus(self.count_a, 1)) #NEVER sucessfully authenticate without updating the count
            self.db.server_poll()
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
                #TESTME, maybe, it's hard
                print "Tag readback not correct, expected: " + str(self.plus(self.count_b, 1)) + " Got: " + str(readback)
                return (False, [])

            self.db.set_tag_count(str(self), self.plus(self.count_b, 1)) #NEVER sucessfully authenticate without updating the count
            self.db.server_poll()

        roles = []
        try:
            roles = self.db.get_user_roles(self.db.get_tag_user(str(self)))
        except EntryDatabaseException as e:
            print "failed to get user roles: " + str(e)

        return (True, roles)

    def log_auth(self, location, result):
        self.db.log_auth(str(self), location, result)

    #return a validated count stored in the sector data given or False
    def validate_sector(self, sector_data, secret):
        #Assert crc16 matches sector or log corrupt sector and return
        payload = "".join(map(chr, sector_data[0:46]))
        crc = (sector_data[46] << 8) + sector_data[47]
        if not crc16.crc16xmodem(payload) == crc:
            #TESTME
            raise TagException("Sector data failed checksum")

        count = (sector_data[0] << 8) + sector_data[1]
        algorithm = sector_data[2]
        cost = sector_data[3]
        digest = self.unencode_bcrypt64(sector_data[4:44])
        reserved = sector_data[44:46]

        if algorithm > (len(self.BCRYPT_VERSION) - 1):
            #TESTME
            raise TagException("Unknown bcrypt algorithm: " + str(algorithm))

        for b in reserved:
            if b != 0:
                #TESTME
                raise TagException("Data in padding")

        read_hash = '$' + str(self.BCRYPT_VERSION[algorithm]) + '$' + str(cost).zfill(2) + '$' + digest

        calculated_hash = bcrypt.hashpw(str(count) + str(secret), read_hash)

        if calculated_hash != read_hash:
            #TESTME
            raise TagException("Hash does not match, count is not authentic.") #TESTME clone tag and make tag with bad signature

        return count

    #return data stored "securely" in given sector
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

    #write a sector to the tag given the count and secret
    def write_sector(self, sector, key, keyspec, secret, count):
        generated_hash = bcrypt.hashpw(str(count) + str(secret), bcrypt.gensalt(self.BCRYPT_COST))
        hash_parts = generated_hash.split("$")

        data = []
        data.append(count >> 8)
        data.append(count & 0xFF)
        data.append(self.BCRYPT_VERSION.index(hash_parts[1])) #bcrypt algorithm
        data.append(int(hash_parts[2])) #cost
        data.extend(self.encode_bcrypt64(hash_parts[3])) #salt & digest
        data.extend([0, 0]) #padding
        crc = crc16.crc16xmodem("".join(map(chr, data))) #crc
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
        if status != nfc.MI_OK:
            raise TagException("Failed to authenticate sector " + str(sector) + " of Tag " + str(self))
        data = []
        data.extend(key_a)
        data.extend(lock_bytes)
        data.extend(key_b)
        (status, backData) = nfc.Write_Block(sector * 4 + 3, data)
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to write sector " + str(sector) + " block " + str(sector * 4 + 3) + " of Tag " + str(self))

    #convert from binary byte array to bcrypt base64
    def unencode_bcrypt64(self, binary_arr):
        base64 = ""
        i = 0
        binary = 0
        for c in binary_arr:
            binary = binary + (c << i)
            i += 8
        for i in range(int(len(binary_arr)*8/6.0)):
            base64 = base64 + str(list(self.BCRYPT_BASE64_DICT)[(binary >> (i * 6)) & 63])
        return base64

    #convert from bcrypt base64 format to binary byte array
    def encode_bcrypt64(self, base64):
        binary_int = 0
        i = 0
        for c in list(base64):
            binary_int = binary_int + (self.BCRYPT_BASE64_DICT.index(c) << i)
            i += 6
        binary = []
        for i in range(int(ceil(len(list(base64))*6/8.0))):
            binary.append(int(((binary_int >> (i * 8)) & 0xff)))
        return binary

    #16-bit wrapping plus function
    def plus(self, left, right):
        return (left + right) % (2**16)

    def subtract(self, left, right):
        return (left - right) % (2**16)

    #16-bit wrapping greater than function
    def greater_than(self, left, right):
        left = (left + (2**16/2)) % (2**16)
        right = (right + (2**16/2)) % (2**16)
        if left == 0 and right == 65535:
            return True
        return left > right

    #16-bit wrapping less than function
    def less_than(self, left, right):
        left = (left + (2**16/2)) % (2**16)
        right = (right + (2**16/2)) % (2**16)
        if left == 65535 and right == 0:
            return True
        return left < right

class TagException(Exception):
    pass

class EntryDatabase:
    proc = None
    mgr = Manager()
    local = mgr.dict() #shared objects
    unsent = mgr.dict()
    server_url = None
    api_key = None

    def __init__(self):
        # load settings
        try:
            rcfile = open('doorrc', 'r')
        except IOError:
            print "Can't read file: 'doorrc', you need that."
            sys.exit(1)

        settings = json.loads(rcfile.read())
        rcfile.close()

        self.server_url = settings['server_url']
        self.api_key = settings['api_key']

        # pull server copy down, if this initial load fails we will exit and let systemd respawn us
        print "Connecting to " + self.server_url
        self.server_pull_now()

    def __del__(self):
        if type(self.proc) is Process and self.proc.is_alive():
            self.proc.terminate()

    #blocking pull of db from server
    def server_pull_now(self):
        try:
            response = requests.get(self.server_url, cookies={'SECRET': self.api_key})
            if response.status_code == requests.codes.ok:
                self.local.update(json.loads(response.text))
            else:
                raise EntryDatabaseException("Server returned bad status to GET: " + str(response.status_code) + " - " + str(response.text))
        except requests.exceptions.RequestException as e:
            raise EntryDatabaseException("GET request error: " + str(e))

    #blocking update of server
    def server_push_now(self):
        try:
            response = requests.post(self.server_url,
                                     cookies={'SECRET': self.api_key},
                                     data = json.dumps(dict(self.unsent)),
                                     headers={'content-type': 'application/json'})
            if response.status_code == requests.codes.ok:
                self.unsent.clear()
            else:
                raise EntryDatabaseException("Server returned bad status to POST:" + str(response.status_code) + " - " + str(response.text))
        except requests.exceptions.RequestException as e:
            raise EntryDatabaseException("POST request error: " + str(e))

    def _server_poll_worker(self, r_unsent, r_local):
        if len(r_unsent) > 0:
            try:
                response = requests.post(self.server_url,
                                         cookies={'SECRET': self.api_key},
                                         data = json.dumps(dict(r_unsent)),
                                         headers={'content-type': 'application/json'})
                if response.status_code == requests.codes.ok:
                    r_unsent.clear()
                else:
                    #there is nobody to catch anything thrown here
                    print "Server returned bad status to POST:" + str(response.status_code)
                    return #do not pull if we failed to push, it may clobber unsent from local
            except requests.exceptions.RequestException as e:
                print "POST request error: " + str(e) + " - " + str(response.text)
                return

        try:
            response = requests.get(self.server_url, cookies={'SECRET': self.api_key})
            if response.status_code == requests.codes.ok:
                r_local = json.loads(response.text)
            else:
                print "Server returned bad status to GET: " + str(response.status_code)
        except requests.exceptions.RequestException as e:
            print "GET request error: " + str(e) + " - " + str(response.text)

    #attempt to send unsent changes to the server and update the local copy, asynchronously
    def server_poll(self):
        if type(self.proc) is Process and self.proc.is_alive():
            print "Server poll still in progress, not starting another."
        else:
            self.proc = Process(target = self._server_poll_worker, args = (self.unsent, self.local))
            self.proc.start()

    def get_tag_user(self, uid):
        try:
            if not self.local.has_key("tags") or not self.local['tags'].has_key(uid):
                raise EntryDatabaseException("Unkown tag")
            if not self.local["tags"][uid].has_key('assigned_user') or self.local["tags"][uid]["assigned_user"] is None:
                raise EntryDatabaseException("Unassigned tag")
            if type(self.local['tags'][uid]['assigned_user']) in [str,unicode]:
                return self.local['tags'][uid]['assigned_user']
            else:
                raise EntryDatabaseException("Assigned user id not string: " + str(self.local['tags'][uid]['assigned_user']))
        except TypeError as e:
            raise EntryDatabaseException("TypeError: " + str(e))

    def set_tag_user(self, uid, user):
        p_local = dict(self.local) #copy and cast the shared object to a real dict before vivifying it
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags',uid,'assigned_user'], user)
        self.vivify(p_unsent, ['tags',uid,'assigned_user'], user)
        self.local.update(p_local) #update after to set the shared object to the content of the dict
        self.unsent.update(p_unsent)

    def get_tag_count(self, uid):
        try:
            if type(self.local['tags'][uid]['count']) is int:
                return self.local['tags'][uid]['count']
            else:
                raise EntryDatabaseException("count not an int: " + str(self.local['tags'][uid]['count'])) #TESTME counts >65535 and <0
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def vivify(self, dic, keys, value):
        key = keys.pop(0)
        if not dic.has_key(key):
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
        self.vivify(p_local, ['tags',uid,'count'], count)
        self.vivify(p_unsent, ['tags',uid,'count'],  count)
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
        self.vivify(p_local, ['tags',uid,'sector_a_sector'], sector)
        self.vivify(p_unsent, ['tags',uid,'sector_a_sector'], sector)
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
        self.vivify(p_local, ['tags',uid,'sector_b_sector'], sector)
        self.vivify(p_unsent, ['tags',uid,'sector_b_sector'], sector)
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_a_key_a(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_a_key_a']) in [str,unicode]:
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
        self.vivify(p_local, ['tags',uid,'sector_a_key_a'], base64.b64encode("".join(map(chr, key))))
        self.vivify(p_unsent, ['tags',uid,'sector_a_key_a'], base64.b64encode("".join(map(chr, key))))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_a_key_b(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_a_key_b']) in [str,unicode]:
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
        self.vivify(p_local, ['tags',uid,'sector_a_key_b'], base64.b64encode("".join(map(chr, key))))
        self.vivify(p_unsent, ['tags',uid,'sector_a_key_b'], base64.b64encode("".join(map(chr, key))))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_b_key_a(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_b_key_a']) in [str,unicode]:
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
        self.vivify(p_local, ['tags',uid,'sector_b_key_a'], base64.b64encode("".join(map(chr, key))))
        self.vivify(p_unsent, ['tags',uid,'sector_b_key_a'], base64.b64encode("".join(map(chr, key))))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_b_key_b(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_b_key_b']) in [str,unicode]:
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
        self.vivify(p_local, ['tags',uid,'sector_b_key_b'], base64.b64encode("".join(map(chr, key))))
        self.vivify(p_unsent, ['tags',uid,'sector_b_key_b'], base64.b64encode("".join(map(chr, key))))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_a_secret(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_a_secret']) in [str,unicode]:
                return base64.b64decode(self.local['tags'][uid]['sector_a_secret'])
            else:
                raise EntryDatabaseException("sector_a_secret is not string: " + str(self.local['tags'][uid]['sector_a_secret']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_a_secret(self, uid, secret):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags',uid,'sector_a_secret'], base64.b64encode(secret))
        self.vivify(p_unsent, ['tags',uid,'sector_a_secret'], base64.b64encode(secret))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_tag_sector_b_secret(self, uid):
        try:
            if type(self.local['tags'][uid]['sector_b_secret']) in [str,unicode]:
                return base64.b64decode(self.local['tags'][uid]['sector_b_secret'])
            else:
                raise EntryDatabaseException("sector_b_secret is not string: " + str(self.local['tags'][uid]['sector_b_secret']))
        except KeyError as e:
            raise EntryDatabaseException("KeyError: " + str(e))

    def set_tag_sector_b_secret(self, uid, secret):
        p_local = dict(self.local)
        p_unsent = dict(self.unsent)
        self.vivify(p_local, ['tags',uid,'sector_b_secret'], base64.b64encode(secret))
        self.vivify(p_unsent, ['tags',uid,'sector_b_secret'], base64.b64encode(secret))
        self.local.update(p_local)
        self.unsent.update(p_unsent)

    def get_user_name(self, userid):
        try:
            if type(self.local['users'][userid]['name']) in [str,unicode]:
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

    def log_auth(self, uid, location, result):
        #vivify cannot append to lists
        scans = []
        try:
            scans = self.unsent['tags'][uid]['scans']
        except KeyError:
            pass

        scans.append({"date": int(time.time()), "location": location, "result": result})

        #this does not need to be stored locally
        p_unsent = dict(self.unsent)
        self.vivify(p_unsent, ['tags',uid,'scans'], scans)
        self.unsent.update(p_unsent)

class EntryDatabaseException(Exception):
    pass

#initialise a tag using well known sector keys #TODO, also get here by pressing a button on the door
if len(sys.argv) > 1:
    if sys.argv[1] != "safe" and sys.argv[1] != "init":
        print "python doord.py [init|safe|help]"
        print ""
        print "The door authentiction server, runs as a deamon with no arguments."
        print "Put the server url and api_key in the doorrc file."
        print "    init - Initialise a tag and add it to thre server."
        print "    safe - Initialise a tag with well known keys ('key a' and"
        print "           'key b', big endian ASCII encoded)."
        print "    help - Show this help document."
        sys.exit(2)

    nfc = MFRC522.MFRC522()
    db = EntryDatabase()
    if sys.argv[1] == "init":
        print "Initing tag with production keys"
    else:
        print "Initing tag with well known keys \"key a\" and \"key b\""
    print "Present tag.."
    status = nfc.MI_NOTAGERR

    # wait for an nfc device to be presented
    while status != nfc.MI_OK:
        (status,TagType) = nfc.MFRC522_Request(nfc.PICC_REQIDL)
    print "NFC device presented"

    (status,uid) = nfc.MFRC522_Anticoll()
    if status == nfc.MI_OK:
        tag = Tag(uid, nfc, db)
        print "Found tag UID: " + str(tag)

        # bcrypt will reject a count padded with a null (chr(0)) character.
        # It will also reject unicode text objects (u"hello") but not unicode
        # characters in a regular string (b"You can't have unicode in python comments")
        while True:
            sector_a_secret = os.urandom(23) #23 because this matches the entropy of the bcrypt digest itself
            if not b"\x00" in sector_a_secret:
                break
        while True:
            sector_b_secret = os.urandom(23)
            if not b"\x00" in sector_b_secret:
                break
        default_key = [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF]
        default_keyspec = nfc.PICC_AUTHENT1A
        # Mifare keys may contain zeros
        if sys.argv[1] == "init":
            sector_a_key_a = map(ord, os.urandom(6))
            sector_a_key_b = map(ord, os.urandom(6))
            sector_b_key_a = map(ord, os.urandom(6))
            sector_b_key_b = map(ord, os.urandom(6))
        else:
            #use well known keys for testing
            sector_a_key_a = [0x6B,0x65,0x79,0x20,0x61,0x00]
            sector_a_key_b = [0x6B,0x65,0x79,0x20,0x62,0x00]
            sector_b_key_a = [0x6B,0x65,0x79,0x20,0x61,0x00]
            sector_b_key_b = [0x6B,0x65,0x79,0x20,0x62,0x00]

        try:
            print "Writing sector 1"
            tag.write_sector(1,
                             default_key,
                             default_keyspec,
                             sector_a_secret,
                             0)
            print "Writing sector 2"
            tag.write_sector(2,
                             default_key,
                             default_keyspec,
                             sector_b_secret,
                             1)
            print "Readback sectors"
            sector_a_backdata = tag.read_sector(1,
                                                default_key,
                                                default_keyspec)
            readback_a = tag.validate_sector(sector_a_backdata,
                                             sector_a_secret)
            if readback_a != 0:
                raise Exception("sector a (1) readback not correct.")

            sector_b_backdata = tag.read_sector(2,
                                                default_key,
                                                default_keyspec)
            readback_b = tag.validate_sector(sector_b_backdata,
                                             sector_b_secret)
            if readback_b != 1:
                raise  Exception("sector b (2) readback not correct.")

            print "Securing sectors"
            tag.configure_sector(1, default_key, default_keyspec, sector_a_key_a, tag.SECTOR_LOCK_BYTES, sector_a_key_b)
            tag.configure_sector(2, default_key, default_keyspec, sector_b_key_a, tag.SECTOR_LOCK_BYTES, sector_b_key_b)

            print "Readback sectors"
            sector_a_backdata = tag.read_sector(1,
                                                sector_a_key_a,
                                                default_keyspec)
            readback_a = tag.validate_sector(sector_a_backdata,
                                             sector_a_secret)
            if readback_a != 0:
                raise Exception("sector a (1) readback not correct.")

            sector_b_backdata = tag.read_sector(2,
                                                sector_b_key_a,
                                                default_keyspec)
            readback_b = tag.validate_sector(sector_b_backdata,
                                             sector_b_secret)
            if readback_b != 1:
                raise Exception("sector b (2) readback not correct.")

            print "Sending tag details to server."
            db.set_tag_user(str(tag), None)
            db.set_tag_count(str(tag), 1)
            db.set_tag_sector_a_sector(str(tag), 1)
            db.set_tag_sector_b_sector(str(tag), 2)
            db.set_tag_sector_a_secret(str(tag), sector_a_secret)
            db.set_tag_sector_b_secret(str(tag), sector_b_secret)
            db.set_tag_sector_a_key_a(str(tag), sector_a_key_a)
            db.set_tag_sector_a_key_b(str(tag), sector_a_key_b)
            db.set_tag_sector_b_key_a(str(tag), sector_b_key_a)
            db.set_tag_sector_b_key_b(str(tag), sector_b_key_b)
            try:
                db.server_push_now()
            except EntryDatabaseException as e:
                raise
            print "Success."

        except Exception as e:
            print "sector a (1):"
            print "  key a: " + str(sector_a_key_a)
            print "  key b: " + str(sector_a_key_b)
            print "sector b (2):"
            print "  key a: " + str(sector_b_key_a)
            print "  key b: " + str(sector_b_key_b)
            print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
            print "FAILED TO WRITE TAG or UPDATE SERVER - WRITE DOWN THE KEYS SHOWN ABOVE AND STICK THEM TO THE TAG RIGHT NOW!!!!"
            print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
            #make doubly sure this gets logged
            syslog.syslog("doord: Failed to init a tag, keys attempted were: sector a (1): key a: " + str(sector_a_key_a) + " key b: " + str(sector_a_key_b) + " sector b (2): key a: " + str(sector_b_key_a) + "  key b: " + str(sector_b_key_b))
            raise

        sys.exit(0)

inst = DoorService()
inst.main()
