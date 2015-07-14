import sys, json, requests
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
	        (status,TagType) = self.nfc.MFRC522_Request(self.nfc.PICC_REQIDL)
	    print "NFC device presented"
	    
	    # run anti-collision and let one id fall out #TODO work out how to select other tags for people presenting a whole wallet.
	    (status,uid) = self.nfc.MFRC522_Anticoll()
	    if status == self.nfc.MI_OK:
	        tag = Tag(uid, self.nfc, self.db)
	        print "Found tag UID: " + tag.str_x_uid()

		#authenticate
		if tag.authenticate:
		    print "Tag " + tag.str_x_uid() + " authenticated"
		    #open the door
		else:
		    print "Tag " + tag.str_x_uid() + " NOT authenticated"

	    else:
	        print "Failed to read UID"


class Tag:
    uid = None
    nfc = None
    db = None
    count = None
    count_a = None
    count_b = None

    def __init__(self, uid, nfc, db):
        self.uid = uid
	self.nfc = nfc
        self.db = db

    def authenticate(self):
        userid = self.db.get_tag_user(self.str_x_uid())
        if userid == None:
            print "Tag " + self.str_x_uid() + " is alien"
            return False

        if self.db.is_tag_blacklisted(self.str_x_uid()):
            print "BLACKLISTED TAG DETECTED: " + self.str_x_uid

        username = self.db.get_user_name(userid)
        print "Tag is assigned to user " + userid + " (" + username + ")"
        
        self.count = self.db.get_tag_count(self.str_x_uid())

        self.nfc.MFRC522_SelectTag(self.uid)

        try:
            sector_a_data = self.read_sector(self.db.get_tag_sector_a_sector(self.str_x_uid()), self.db.get_tag_sector_a_key_b(self.str_x_uid()), self.nfc.PICC_AUTHENT1B) #TODO test missinig fields
            sector_b_data = self.read_sector(self.db.get_tag_sector_b_sector(self.str_x_uid()), self.db.get_tag_sector_b_key_b(self.str_x_uid()), self.nfc.PICC_AUTHENT1B)
        except Exception as e:
            #TODO test me
            print "Failed to Read sector: " + e
            return

        print sector_a_data
        print sector_b_data

        #self.count_a = self.validate_sector(sector_a_data, self.db.get_tag_sector_a_secret(self.str_x_uid()))
        #self.count_b = self.validate_sector(sector_b_data, self.db.get_tag_sector_b_secret(self.str_x_uid()))

        nfc.MFRC522_StopCrypto1() #TODO work out the correct time to run this.
        return True

    def validate_sector(self, sector_data, secret):
        #do the things
        return count

    def read_sector(self, sector, key, keyspec):
        status = self.nfc.Auth_Sector(keyspec, sector, key, self.uid)
        if (status != self.nfc.MI_OK):
            raise Exception("Failed to authenticate sector " + sector + " of Tag " + self.str_x_uid())

        (status, data) = self.nfc.Read_Sector(sector)
        if (status != self.nfc.MI_OK):
            raise Exception("Failed to read sector " + sector + " of Tag " + self.str_x_uid())

        return data
        
    def str_x_uid(self):
        return format(self.uid[0], "x") + format(self.uid[1], "x") + format(self.uid[2], "x") + format(self.uid[3], "x")

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

    #getters to keep the "database" schema out of the auth code
    def get_tag_count(self, uid):
        return self.local['tags'][uid]['count']

    def get_tag_sector_a_sector(self, uid):
        return self.local['tag'][uid]['sector_a_sector']

    def get_tag_sector_b_sector(self, uid):
        return self.local['tag'][uid]['sector_b_sector']

    def get_tag_sector_a_key_a(self, uid):
        return map(ord, self.local['tag'][uid]['sector_a_key_a'])
    
    def get_tag_sector_a_key_b(self, uid):
        return map(ord, self.local['tag'][uid]['sector_a_key_b'])
    
    def get_tag_sector_b_key_a(self, uid):
        return map(ord, self.local['tag'][uid]['sector_b_key_a'])
    
    def get_tag_sector_b_key_b(self, uid):
        return map(ord, self.local['tag'][uid]['sector_b_key_b'])
    
    def get_tag_sector_a_secret(self, uid):
        return self.local['tag'][uid]['sector_a_secret']

    def get_tag_sector_b_secret(self, uid):
        return self.local['tag'][uid]['sector_b_secret']

    def get_user_name(self, userid):
        return self.local['users'][userid]['name']


inst = DoorService()
inst.main()
