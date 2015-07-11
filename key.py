import base64

k = [0x6B,0x65,0x79,0x20,0x62,0x00]
s = ""
for i in k:
  s = s + chr(i)

print s

print base64.b64encode(s)
