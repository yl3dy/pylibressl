from cryptomodule.crypto import encrypt, decrypt
data = b'This is a test message for GOST.'
key =  b'1'*32
iv =   b'2'*16

enc = encrypt(data, (key, iv, 'gost'))
print(enc)
dec = decrypt(enc, (key, iv, 'gost'))
print(dec)
