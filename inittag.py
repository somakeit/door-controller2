import bcrypt, crc16
import requests, json, base64
import sys

RANDOM_SOURCE = '/dev/urandom'
SECRET_SIZE = 23      #bcrypt digest size
SERVER_POST_URL = 'http://localhost:8000'    #use SSL
api_key = 'lol'

#read card NUID
sys.stdout.write("Present tag..\n")
nuid = 0
sys.stdout.write("NUID: " + str(nuid) + "\n")

#generate credentials
sys.stdout.write("Generating credentials..\n")
data = {'tags':{nuid: {}}}
random = open(RANDOM_SOURCE, 'r')
data['tags'][nuid]['sector_a_sector'] = 1 #allows us to use any pair of sectors on the tag
data['tags'][nuid]['sector_a_count'] = 0
data['tags'][nuid]['sector_a_secret'] = base64.b64encode(random.read(SECRET_SIZE))
data['tags'][nuid]['sector_a_key_a'] = base64.b64encode(random.read(6))
data['tags'][nuid]['sector_a_key_b'] = base64.b64encode(random.read(6))
data['tags'][nuid]['sector_b_sector'] = 2
data['tags'][nuid]['sector_b_count'] = 1
data['tags'][nuid]['sector_b_secret'] = base64.b64encode(random.read(SECRET_SIZE))
data['tags'][nuid]['sector_b_key_a'] = base64.b64encode(random.read(6))
data['tags'][nuid]['sector_b_key_b'] = base64.b64encode(random.read(6))
random.close()

#write card
sys.stdout.write("Writing to tag..\n")
print json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
sys.stdout.write("Validating tag..\n")

#send to server
sys.stdout.write("Writing credentials to database..\n")

data = json.dumps(data)
cookies = {'api_key': api_key}
requests.post(SERVER_POST_URL, data=data, cookies=cookies)
