from cryptography.fernet import Fernet

import unittest
import random
import string
import hashlib

import vault

TEST_CASES = [
    (b'simple string', 'simplepassword'),
    (b'm0r#@$e com|}{{\][qex \t\n\0 sttring', '!^#$|A{+VAasdfaw\n\r\\'),
    (b'', '')
]

def setup_module():
    print ("setup           class:TestBasicStuff")
    for _ in range(0, 100):
        data_length = random.randint(0,10000)
        pw_length = random.randint(1, 100)
        data = _get_random_byte_array(data_length)
        pw = _get_random_string(pw_length)
        # print('adding (%s, %s) to testcases' % (data, pw))
        TEST_CASES.append((data, pw))
        
def test_encrypt_and_decrypt_bytes():
    for (data, password) in TEST_CASES:
        print('running (%s, %s)' % (data, password))
        crypto_bytes = vault._encrypt_bytes(data, password)
        back_to_raw = vault._decrypt_bytes(crypto_bytes, password)
        
        assert data == back_to_raw
            
def _get_random_byte_array(length):
    return bytes([random.randint(0,255) for _ in range(0, length)])

def _get_random_string(length):
    char_pool = [chr(x) for x in range(32, 128)]
    return ''.join([random.choice(char_pool) for _ in range(0, length)])
    
setup_module()
    
