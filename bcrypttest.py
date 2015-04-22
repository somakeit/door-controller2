import bcrypt, sys, crc16

BCRYPT_BASE64_DICT = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
BCRYPT_VERSION = ['2', '2a', '2y']

string = 'Hello world!'

hashed = bcrypt.hashpw(string, bcrypt.gensalt(12))

print hashed

parts = hashed.split('$')

version = BCRYPT_VERSION.index(parts[1])

cost = int(parts[2])

binary = 0
i = 0
for c in list(parts[3]):
    binary = binary + (BCRYPT_BASE64_DICT.index(c) << i)
    i += 6

cardable = [version, 0, 0] #reserved bytes
cardable.append(cost);
for i in range(40):
    cardable.append(int(((binary >> (i * 8)) & 0xff)))

csum = crc16.crc16xmodem(hashed)
print csum

cardable.append(csum >> 8)
cardable.append(csum & 255)
cardable.append(0) #reserved bytes
cardable.append(0)

print cardable
#cardable[10] = cardable[10] + 1 #bit error
#print cardable

#################################################################

csum2 = (cardable.pop(44) << 8) + cardable.pop(44)
reserved = cardable.pop(len(cardable)-1)
reserved = cardable.pop(len(cardable)-1)
version2 = BCRYPT_VERSION[cardable.pop(0)]
reserved = cardable.pop(0)
reserved = cardable.pop(0)
cost2 = cardable.pop(0)

binary2 = 0
i = 0
for c in cardable:
    binary2 = binary2 + (c << i)
    i += 8

saltdigest2 = ''
for i in range(53):
    saltdigest2 = saltdigest2 + str(list(BCRYPT_BASE64_DICT)[(binary2 >> (i * 6)) & 63])

hashed2 = '$' + str(version2) + '$' + str(cost2) + '$' + saltdigest2
print hashed2

csum3 = crc16.crc16xmodem(hashed2)
print csum3
if (csum2 == csum3):
    print 'valid'
else:
    print 'INVALID'
