"""Quick and dirty tests."""

from cryptomodule import hash, encrypt, decrypt

print('### GOST 89 encryption test')
data = b'This is a test message for GOST.'
key =  b'1'*32
iv =   b'2'*16

enc = encrypt(data, (key, iv, 'gost'))
print(enc)
dec = decrypt(enc, (key, iv, 'gost'))
print(dec)
print('Encrypt test: ' + ('PASSED' if data == dec else 'FAILED') + '\n')

print('### GOST R 34.11.2012 digest test')
hash_data = b'This is message to hash.'
dgst = hash(hash_data)
print(dgst)
print('Digest length', len(dgst), 'bytes')
