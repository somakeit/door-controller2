import sys, os, json, requests, base64
import crc16, bcrypt
sys.path.append("MFRC522-python")
import MFRC522

class DoorService:
    nfc = None
    db = None

    def __init__(self):
        self.nfc = MFRC522.MFRC522()
        self.db = EntryDatabase()
        print "Initialised"

    def main(self):
        while True:
            status = self.nfc.MI_NOTAGERR

	    # wait for an nfc device to be presented
	    while status != self.nfc.MI_OK:
                #TODO a polling rate to reduce CPU use and tag de-bounce
	        (status,TagType) = self.nfc.MFRC522_Request(self.nfc.PICC_REQIDL)
	    print "NFC device presented"
	    
	    # run anti-collision and let one id fall out #TODO work out how to select other tags for people presenting a whole wallet. We should get an array of UIDs.
	    (status,uid) = self.nfc.MFRC522_Anticoll()
            if status == self.nfc.MI_OK:
	        tag = Tag(uid, self.nfc, self.db)
	        print "Found tag UID: " + tag.str_x_uid()

		#authenticate
		if tag.authenticate():
		    print "Tag " + tag.str_x_uid() + " authenticated"
		    #TODO open the door
		else:
		    print "Tag " + tag.str_x_uid() + " NOT authenticated"

                del tag

	    else:
	        print "Failed to read UID"

class Tag:
    uid = None
    nfc = None
    db = None
    count = None    #the correct count
    count_a = None  #counts read from tag
    count_b = None
    sector_a_ok = True
    sector_b_ok = True
    BCRYPT_BASE64_DICT = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    BCRYPT_VERSION = ['2', '2a', '2b', '2y']
    BCRYPT_COST = 12    #tuned for performance, we must hash 4 times per authentication, this could be reduced to 3 if needed (TODO that)

    #create tag object representing one session with one tag
    def __init__(self, uid, nfc, db):
        self.uid = uid
	self.nfc = nfc
        self.db = db

    #attempt the whole authentication process with this tag
    def authenticate(self):
        userid = self.db.get_tag_user(self.str_x_uid())
        if userid == None:
            #TESTME
            print "Tag " + self.str_x_uid() + " is alien"
            return False

        if self.db.is_tag_blacklisted(self.str_x_uid()):
            #TESTME
            print "BLACKLISTED TAG DETECTED: " + self.str_x_uid
            return False

        username = self.db.get_user_name(userid)
        print "Tag is assigned to user " + userid + " (" + username + ")"
        
        self.count = self.db.get_tag_count(self.str_x_uid())

        self.nfc.MFRC522_SelectTag(self.uid)

        try:
            sector_a_data = self.read_sector(self.db.get_tag_sector_a_sector(self.str_x_uid()),
                                             self.db.get_tag_sector_a_key_b(self.str_x_uid()),
                                             self.nfc.PICC_AUTHENT1B) #TESTME test missinig fields
        
            sector_b_data = self.read_sector(self.db.get_tag_sector_b_sector(self.str_x_uid()),
                                             self.db.get_tag_sector_b_key_b(self.str_x_uid()),
                                             self.nfc.PICC_AUTHENT1B)
        except TagException as e:
            #TESTME one and both
            print "Failed to Read sector: " + str(e)
            return False
        
        try:
            self.count_a = self.validate_sector(sector_a_data,
                                                self.db.get_tag_sector_a_secret(self.str_x_uid()))
        except TagException as e:
            print "Failed to validate sector a: " + str(e)
            self.sector_a_ok = False
        try:
            self.count_b = self.validate_sector(sector_b_data,
                                                self.db.get_tag_sector_b_secret(self.str_x_uid()))
        except TagException as e:
            print "Failed to validate sector b: " + str(e)
            self.sector_b_ok = False

        if (self.sector_a_ok == False) and (self.sector_b_ok == False):
            print "Failed to authenticate, both sectors corrupt"
            return False

        if self.sector_a_ok and seld.sector_b_ok and (abs(self.count_a - self.count2) > 1):
            #TESTME
            print "Warning: valid sector counts spaced higher than expected; A: " + str(self.count_a) + " B: " + str(self.count_b)
        if self.sector_a_ok and seld.sector_b_ok and (self.count_a == self.count_b):
            print "Warning: valid sector counts spaced lower than expected; A: " + str(self.count_a) + " B: " + str(self.count_b)
        
        if self.greater_than(self.count_a, self.count_b) or (not sector_b_ok):
            if self.less_than(iself.count_a, self.count):
                print "Duplicate card detected, expected count: " + str(self.count) + " Found count: " + str(self.count_a)
                return False
            try:
                self.write_sector(self.db.get_tag_sector_b_sector(self.str_x_uid()),
                                  self.db.get_tag_sector_b_key_b(self.str_x_uid()),
                                  self.nfc.PICC_AUTHENT1B,
                                  self.db.get_tag_sector_b_secret(self.str_x_uid()),
                                  self.plus(self.count_a, 1))
                sector_b_backdata = self.read_sector(self.db.get_tag_sector_b_sector(self.str_x_uid()),
                                                     self.db.get_tag_sector_b_key_b(self.str_x_uid()),
                                                     self.nfc.PICC_AUTHENT1B)
                readback = self.validate_sector(sector_b_backdata,
                                                self.db.get_tag_sector_b_secret(self.str_x_uid()))
            except TagException as e:
                print "Failed to update tag: " + str(e)
                return False

            if readback != (self.plus(self.count_a, 1)):
                #TESTME, maybe, it's hard
                print "Tag readback not correct, expected: " + str(self.plus(self.count_a, 1)) + " Got: " + str(readback)
                return False
        else:
            if self.less_than(self.count_b, self.count):
                print "Duplicate card detected, expected count: " + str(self.count) + " Found count: " + str(self.count_b)
                return False
            try:
                self.write_sector(self.db.get_tag_sector_a_sector(self.str_x_uid()),
                                  self.db.get_tag_sector_a_key_b(self.str_x_uid()),
                                  self.nfc.PICC_AUTHENT1B,
                                  self.db.get_tag_sector_a_secret(self.str_x_uid()),
                                  self.plus(self.count_b, 1))
                sector_a_backdata = self.read_sector(self.db.get_tag_sector_a_sector(self.str_x_uid()),
                                                     self.db.get_tag_sector_a_key_b(self.str_x_uid()),
                                                     self.nfc.PICC_AUTHENT1B)
                readback = self.validate_sector(sector_a_backdata,
                                                self.db.get_tag_sector_a_secret(self.str_x_uid()))
            except TagException as e:
                print "Failed to update tag: " + str(e)
                return False

            if readback != (self.plus(self.count_b, 1)):
                #TESTME, maybe, it's hard
                print "Tag readback not correct, expected: " + str(self.plus(self.count_b, 1)) + " Got: " + str(readback)
                return False
        
        return True

    #return a validated count stored in the sector data given or False
    def validate_sector(self, sector_data, secret):
        #Assert crc16 matches sector or log corrupt sector and return
        payload = "".join(map(chr, sector_data[0:45]))
        crc = (sector_data[46] << 8) + sector_data[47]
        if not crc16.crc16xmodem(payload) == crc:
            #TESTME
            raise TagException("Sector data failed checksum")

        count = (sector[0] << 8) + sector[1]
        algorithm = sector_data[2]
        cost = sector_data[3]
        digest = self.unencode_bcrypt64(sector_data[4:43])
        reserved = sector_data[44:45]
        
        if algorithm > (len(self.BCRYPT_VERSION) - 1):
            #TESTME
            raise TagException("Unknown bcrypt algorithm")
        
        for b in reserved:
            if b != 0:
                #TESTME
                raise TagException("Data in padding")

        read_hash = '$' + str(self.BCRYPT_VERSION[algorithm]) + '$' + str(cost) + '$' + digest
        
        calculated_hash = bcrypt.haspw(str(count) + str(secret), read_hash)

        if calculated_hash != read_hash:
            #TESTME
            return False

        return count

    #return data stored "securely" in given sector
    def read_sector(self, sector, key, keyspec):
        status = self.nfc.Auth_Sector(keyspec, sector, key, self.uid)
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to authenticate sector " + str(sector) + " of Tag " + self.str_x_uid())

        (status, data) = self.nfc.Read_Sector(sector)
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to read sector " + str(sector) + " of Tag " + self.str_x_uid())

        return data
        
    def str_x_uid(self):
        return format(self.uid[0], "x") + format(self.uid[1], "x") + format(self.uid[2], "x") + format(self.uid[3], "x")

    #write a sector to the tag given the count and secret
    def write_sector(self, sector, key, keyspec, secret, count):
        generated_hash = bcrypt.hashpw(str(count) + str(secret), bcrypt.gensalt(slef.BCRYPT_COST))
        hash_parts = "$".split(generated_hash)

        data = []
        data.append(count >> 8)
        data.append(count & 0xFF)
        data.append(self.BCRYPT_VERSION.index(hash_parts[1])) #bcrypt algorithm
        data.append(int(hash_parts[2])) #cost
        data.append(self.encode_bcrypt64(hash_parts[3])) #salt & digest
        data.append([0, 0]) #padding
        data.append(crc16.crc16xmodem("".join(map(chr, data)))) #crc
        
        status = nfc.Auth_Block(keyspec, sector * 4, key, self.uid)
        if status != nfc.MI_OK:
            raise TagException("Failed to read sector " + str(sector) + " of Tag " + self.str_x_uid())
        (status, backData) = nfc.Write_Block(sector * 4, data[0,15])
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to write sector " + str(sector) + " block " + str(sector * 4) + " of Tag " + self.str_x_uid())
        (status, backData) = nfc.Write_Block(sector * 4 + 1, data[16,31])
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to write sector " + str(sector) + " block " + str(sector * 4 + 1) + " of Tag " + self.str_x_uid())
        (status, backData) = nfc.Write_Block(sector * 4 + 2, data[32,47])
        if (status != self.nfc.MI_OK):
            raise TagException("Failed to write sector " + str(sector) + " block " + str(sector * 4 + 2) + " of Tag " + self.str_x_uid())

    #convert from binary byte array to bcrypt base64
    def unencode_bcrypt64(binary):
        base64 = ""
        for i in range(len(binary)):
            base64 = base64 + str(list(self.BCRYPT_BASE64_DICT)[(binary >> (i * 6)) & 63])
        return base64

    #convert from bcrupt base64 format to binary byte array
    def encode_bcrypt64(base64):
        binary_int = 0
        i = 0
        for c in list(base64):
            binary_int = binary_int + (self.BCRYPT_BASE64_DICT.index(c) << i)
            i += 6
        binary = []
        for i in range(len(base64)/8*6):
            binary.append(int(((binary_int >> (i * 8)) & 0xff)))
        return binary            

    #16-bit wrapping plus function
    def plus(self, left, right):
        return (left + right) % (2**16)

    #16-bit wrapping greater than function
    def greater_than(self, left, right):
        left = (left + (2**16/2)) % (2**16)
        right = (right + (2**16/2)) % (2**16)
        return left > right

    #16-bit wrapping less than function
    def less_than(self, left, right):
        left = (left + (2**16/2)) % (2**16)
        right = (right + (2**16/2)) % (2**16)
        return left < right

    def __del__(self):
        self.nfc.MFRC522_StopCrypto1()

class TagException(Exception):
    pass

class EntryDatabase:
    local = None
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

        # pull server copy down, if this initial load fails we will exit and let systemd respawn us, TODO: think about if we want to keep the cache on disk too
        print "Connecting to " + self.server_url
        response = requests.get(self.server_url, {'api_key': self.api_key})
        self.local = json.loads(response.text)

    def get_tag_user(self, uid):
        if self.local['tags'].has_key(uid):
            return self.local['tags'][uid]['assigned_user']
        else:
            return None

    def is_tag_blacklisted(self, uid):
        if self.local['tags'][uid]['blacklisted']:
            return True
        else:
            return False
    
    def blacklist_tag(uid):
        return #TODO

    #getters to keep the "database" schema out of the auth code
    def get_tag_count(self, uid):
        return self.local['tags'][uid]['count']

    def get_tag_sector_a_sector(self, uid):
        return self.local['tags'][uid]['sector_a_sector']

    def get_tag_sector_b_sector(self, uid):
        return self.local['tags'][uid]['sector_b_sector']

    def get_tag_sector_a_key_a(self, uid):
        return map(ord, base64.b64decode(self.local['tags'][uid]['sector_a_key_a']))
    
    def get_tag_sector_a_key_b(self, uid):
        return map(ord, base64.b64decode(self.local['tags'][uid]['sector_a_key_b']))
    
    def get_tag_sector_b_key_a(self, uid):
        return map(ord, base64.b64decode(self.local['tags'][uid]['sector_b_key_a']))
    
    def get_tag_sector_b_key_b(self, uid):
        return map(ord, base64.b64decode(self.local['tags'][uid]['sector_b_key_b']))
    
    def get_tag_sector_a_secret(self, uid):
        return self.local['tags'][uid]['sector_a_secret']

    def get_tag_sector_b_secret(self, uid):
        return self.local['tags'][uid]['sector_b_secret']

    def get_user_name(self, userid):
        return self.local['users'][userid]['name']

#initialise a tag using well known sector keys
if sys.argv[1] == "safetag":
    nfc = MFRC522.MFRC522()
    db = EntryDatabase()
    print "Initing tag with well known keys \"key a\" and \"key b\""
    status = nfc.MI_NOTAGERR

    # wait for an nfc device to be presented
    while status != self.nfc.MI_OK:
        (status,TagType) = self.nfc.MFRC522_Request(self.nfc.PICC_REQIDL)
        print "NFC device presented"
	    
        # run anti-collision and let one id fall out #TODO work out how to select other tags for people presenting a whole wallet. We should get an array of UIDs.
        (status,uid) = self.nfc.MFRC522_Anticoll()
        if status == self.nfc.MI_OK:
	    tag = Tag(uid, nfc, db)
	    print "Found tag UID: " + tag.str_x_uid()

            sector_a_secret = os.urandom(23)
            sector_b_secret = os.urandom(23)
            sector_a_key_a = [0x6B,0x65,0x79,0x20,0x61,0x00]
            sector_a_key_b = [0x6B,0x65,0x79,0x20,0x62,0x00]
            sector_b_key_a = [0x6B,0x65,0x79,0x20,0x61,0x00]
            sector_b_key_b = [0x6B,0x65,0x79,0x20,0x62,0x00]
            sector_lock_bytes = [0x7F,0x07,0x88,0x69]

            self.write_sector(1,
                              [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF],
                              self.nfc.PICC_AUTHENT1B,
                              sector_a_secret,
                              0)
            slef.write_sector(2,
                              [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF],
                              self.nfc.PICC_AUTHENT1B,
                              sector_b_secret,
                              1)

    sys.exit(0)

inst = DoorService()
inst.main()
