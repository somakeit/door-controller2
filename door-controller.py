import bcrypt, sys

BCRYPT_BASE64_DICT = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

string = 'Hello world!'

#TODO ensure "2a" format is always used
hashed = bcrypt.hashpw(string, bcrypt.gensalt(12))

print hashed

parts = hashed.split('$')

print parts[3]

binary = 0
i = 0
for c in list(parts[3]):
    binary = binary + (BCRYPT_BASE64_DICT.index(c) << i)
    i += 6

print binary

cardable = []
for i in range(40):
    cardable.append(int(((binary >> (i * 8)) & 0xff)))

print cardable

#################################################################

binary2 = 0
i = 0
for c in cardable:
    binary2 = binary2 + (c << i)
    i += 8

print binary2

hashed2 = ''
for i in range(53):
    hashed2 = hashed2 + str(list(BCRYPT_BASE64_DICT)[(binary2 >> (i * 6)) & 63])

print hashed2

sys.stdout.write('$2a$12$')
print hashed2
