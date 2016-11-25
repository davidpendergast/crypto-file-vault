from cryptography.fernet import Fernet

import random
import string

import vault

#key = Fernet.generate_key()
#print('len, key = %d, %s' % (len(key), key))

# token = f.encrypt(b"my deep dark secret")

#random.seed('biscuits')

#char_pool = string.ascii_uppercase + string.ascii_lowercase + string.digits + '-'
#key = ''.join([random.choice(char_pool) for _ in range(0, 43)]) + '='
#key = bytes(key, 'utf-8')
#print('len, key = %d, %s' % (len(key), key))
#key = bytes('MnKV4MsFDj8B-N5z4k7hMblZSzU6FONFT8uKpqhUyyE=', 'utf-8')
#print('len, key = %d, %s' % (len(key), key))

#raw_str = 'this is a string'
#f = Fernet(key)
#token = f.encrypt(bytes(raw_str, 'utf-32'))   
#print(token)

pw = 'bunnies'
raw_data = bytes('{json: [1, 2, 3]}', 'utf-8')


token = vault._encrypt_data(raw_data, pw)

stringify = token.decode('utf-8')
print(stringify)
back_to_bytes = bytes(stringify, 'utf-8')

back_to_raw = vault._decrypt_data(token, pw)


print(back_to_raw.decode('utf-8'))

#def _encrypt_data(raw_data, password):
#    key = _password_to_key(password)
#    f = Fernet(key)
#    crypto_bytes = f.encrypt(raw_data)
#    return crypto_bytes
     
#def _decrypt_data(crypto_data, password):
#    key = _password_to_key(password)
#    f = Fernet(key)
#    token = f.decrypt(crypto_string_data)
#    return token
