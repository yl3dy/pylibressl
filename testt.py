from cryptomodule.crypto import encrypt
data = 'adslkjiowejfiwe'
key =  '1'*32
iv =   '2'*16

enc = encrypt(data, (key, iv, 'gost'))
print(enc)
