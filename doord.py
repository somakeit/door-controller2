import sys, json, requests
sys.path.append("MFRC522-python")
import MFRC522

class DoorService:
    nfc = None
    dbase = None

    def __init__(self):
        self.nfc = MFRC522.MFRC522()
        self.dbase = EntryDatabase()

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
	        tag = Tag(uid, self.nfc)
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

    def __init__(self, uid, nfc):
        self.uid = uid
	self.nfc = nfc

    def authenticate(self):
        #placeholder
	self.nfc.MFRC522_SelectTag(self.uid)
	status = self.nfc.Auth_Sector(self.nfc.PICC_AUTHENT1A, 0, [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF], self.uid)
	if status != self.nfc.MI_OK:
	    print "Authentication error"
	    return False
	(status, data) = self.nfc.Read_Sector(sector)
	if status == self.nfc.MI_OK:
	    print data
	else:
	    print "Read error"
	    return False

        nfc.MFRC522_StopCrypto1() #TODO work out the correct time to run this.
	return True
        
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

        # pull server copy down, if this initial load fails we will exit and let systemd respawn us
        response = requests.get(self.server_url, {'api_key': self.api_key})
        self.local = json.loads(response.text)
        print self.local

inst = DoorService()
inst.main()
