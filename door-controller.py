import bcrypt, sys

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

print cardable

#################################################################

version2 = BCRYPT_VERSION[cardable.pop(0)]
reserved = cardable.pop(0)
reserved = cardable.pop(0)
cost2 = cardable.pop(0)

binary2 = 0
i = 0
for c in cardable:
    binary2 = binary2 + (c << i)
    i += 8

hashed2 = ''
for i in range(53):
    hashed2 = hashed2 + str(list(BCRYPT_BASE64_DICT)[(binary2 >> (i * 6)) & 63])

sys.stdout.write('$')
sys.stdout.write(str(version2))
sys.stdout.write('$')
sys.stdout.write(str(cost2))
sys.stdout.write('$')
print hashed2
