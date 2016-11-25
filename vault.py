"""
    vault.py
    ~~~~~~~~
    
    Encrypts and decrypts files.
    
    :author: dpendergast
"""

from cryptography.fernet import Fernet

import sys
import os.path
import re
import getpass
import hashlib
import json
import random
import string
import base64

"""if true, exceptions are raised on failure instead of exiting."""
TESTING_MODE = False

HELP_FLAG = '--help'

DATA_FILENAME = 'vaultdata.json'
OUTPUT_DIRECTORY = 'secret_files'
INPUT_DIRECTORY = 'plain_files'
    
def encrypt():
    """encryption command sequence"""
    _verify_initted()
    targets = _get_targets_for_encryption()
    _ask_for_user_confirm_on_targets(targets, 'encrypt')
    password = _ask_for_password()
    
    do_encryption(targets, password)
    
def decrypt():
    """decryption command sequence"""
    _verify_initted()
    targets = _get_targets_for_decryption()
    _ask_for_user_confirm_on_targets(targets, 'decrypt')
    password = _ask_for_password()
    
    do_decryption(targets, password)
    
def status():
    """status command sequence"""
    encrypt_targets = _get_targets_for_encryption()
    decrypt_targets = _get_targets_for_decryption()
     
    print('\nThere are %d files to encrypt:' % len(encrypt_targets))
    if len(encrypt_targets) > 0:
        print('\n'.join(['\t' + x for x in encrypt_targets]))
    
    print('\nThere are %d files to decrypt:' % len(decrypt_targets))
    if len(decrypt_targets) > 0:
        print('\n'.join(['\t' + x for x in decrypt_targets]))
    
def init():
    """init command sequence"""
    if _is_initted():
        _fail('vault is already initialized in this directory.')
    
    print('Choose a password:')
    
    password = ''
    while True:
        password = getpass.getpass('Password: ')
        password_confirm = getpass.getpass('Confirm password: ')
        if _new_password_is_valid(password, password_confirm):
            break
            
    pw_hash = _hash(password)
    json_blob = {
        'pw_hash':pw_hash
    }
    
    print('Creating %s...' % DATA_FILENAME)
    with open(DATA_FILENAME, 'w') as outfile:
        json.dump(json_blob, outfile)
        
    print('Creating %s...' % OUTPUT_DIRECTORY)
    _make_dir_if_necessary(OUTPUT_DIRECTORY)
    print('Creating %s...' % INPUT_DIRECTORY)
    _make_dir_if_necessary(INPUT_DIRECTORY)
    
    print('Vault successfully initialized.')
     
def help():
    """--help command sequence"""
    text = [
        'usage: vault.py [option]',
        'Options corresponding to Vault functions:',
        'init    : Initialize a new Vault password and ',
        'encrypt : Encrypt the contents of plain_files',
        'decrypt : Decrypt the contents of secret_files',
        'status  : Display lists of currently encrypted and non-encrypted files',
        '--help  : Show this info'
    ]
    
    print('\n'.join(text))
    
    
def do_encryption(targets, password):
    password_hash = _hash(password)
    _make_dir_if_necessary(OUTPUT_DIRECTORY)
    created_files = []
    removed_files = []
    unaffected_files = []
    
    filenames = _get_unique_filenames(len(targets), '.json', OUTPUT_DIRECTORY)
    
    for target in targets:
        if is_encrypted(target):
            print('Skipping already encrypted file: %s' % target)
            unaffected_files.append(target)
        else:
            try:
                with open(target, 'rb') as data_file:
                    print('encrypting %s...' % target)
                    raw_data = data_file.read()
                    as_ints = [int(x) for x in raw_data]
                    json_blob = {
                        'file_name':target,
                        'file_contents':as_ints
                    }
                    json_string = json.dumps(json_blob) 
                    as_bytes = bytes(json_string, 'utf-8')
                    crypto_bytes = _encrypt_data(as_bytes, password)
                    crypto_string = crypto_bytes.decode('utf-8')
                    actual_json = {
                        'pw_hash':password_hash,
                        'crypto_data':crypto_string
                    }
                    
                    filename = filenames.pop()
                    full_name = os.path.join(OUTPUT_DIRECTORY, filename)
                    
                    with open(full_name, 'w') as out_file:
                        json.dump(actual_json, out_file, indent=4)
                    created_files.append(full_name)
                
                os.remove(target)
                removed_files.append(target)
                
            except Exception as e:
                print('Exception thrown while encrypting file: %s' % target)
                print(e)
                unaffected_files.append(target)
                
    _display_summary(created_files, removed_files, unaffected_files)

def _get_unique_filenames(n, filetype, for_directory):
    dir_files = set(os.listdir(for_directory))
    filenames = []
    while len(filenames) < n:
        rand_num = random.randint(0, 1000000000)
        hex_str = hex(rand_num)
        name = hex_str[2:] + filetype
        if name not in dir_files:
            filenames.append(name)
    return filenames

def _make_dir_if_necessary(directory_name):
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)
    
def do_decryption(targets, password):
    password_hash = _hash(password)
    created_files = []
    removed_files = []
    unaffected_files = []
    
    for target in targets:
        if not is_encrypted(target):
            print('Skipping non-encrypted file: %s' % target)
            unaffected_files.append(target)
        else:
            try:
                with open(target, 'r') as data_file:    
                    json_blob = json.load(data_file)
                    if password_hash != json_blob['pw_hash']:
                        raise Exception('File encrypted with different password: %s' % target)
                    
                    crypto_string = json_blob['crypto_data'] 
                    crypto_bytes = bytes(crypto_string, 'utf-8')
                    print('decrypting %s...' % target)
                    
                    raw_bytes = _decrypt_data(crypto_bytes, password)
                    json_string = raw_bytes.decode('utf-8')
                    json_blob = json.loads(json_string)
                    file_name = json_blob['file_name']
                    file_contents = json_blob['file_contents']
                    
                    as_bytes = bytes(file_contents)
                    write_file(file_name, as_bytes)
                    
                    created_files.append(file_name)
                
                os.remove(target)
                removed_files.append(target)
            except Exception as e:
                print('Exception thrown while reading file: %s' % target)
                print(e)
                unaffected_files.append(target)
    _display_summary(created_files, removed_files, unaffected_files)

def _display_summary(created_files, removed_files, unaffected_files):
    print('\nCreated %d files:' % len(created_files))
    print('\n'.join(['\t' + x for x in created_files]))
    print('\nRemoved %d files:' % len(removed_files))
    print('\n'.join(['\t' + x for x in removed_files]))
    if len(unaffected_files) > 0:
        print('\n%d files unaffected:' % len(unaffected_files))
        print('\n'.join(['\t' + x for x in unaffected_files]))
     
def _encrypt_data(raw_data, password):
    key = _password_to_key(password)
    f = Fernet(key)
    crypto_bytes = f.encrypt(raw_data)
    return crypto_bytes
     
def _decrypt_data(crypto_data, password):
    key = _password_to_key(password)
    f = Fernet(key)
    token = f.decrypt(crypto_data)
    return token
    
def _password_to_key(password):
    char_pool = string.ascii_uppercase + string.ascii_lowercase
    char_pool +=  string.digits + '-'
    
    random.seed(password)
    key_str = ''.join([random.choice(char_pool) for _ in range(0, 43)]) + '='
    key = bytes(key_str, 'utf-8')
    return key
    
def write_file(file_name, file_contents):
    try:
        dir_path = os.path.dirname(file_name)
        os.makedirs(dir_path)
    except Exception:
        pass # probably the directory just already exists.
        
    with open(file_name,'wb') as f:
        f.write(file_contents)
                    
def is_encrypted(target):
    """returns true if target filename is already encrypted."""
    try:
        with open(target) as data_file:    
            data = json.load(data_file)
            return 'pw_hash' in data and 'crypto_data' in data
    except:
        return False
    
def _get_targets_for_encryption():
    targets = _get_targets(INPUT_DIRECTORY)
    return [x for x in targets if not is_encrypted(x)]
    
def _get_targets_for_decryption():
    targets = _get_targets(OUTPUT_DIRECTORY)
    return [x for x in targets if is_encrypted(x)]
    
def _verify_initted():
    if not _is_initted():
        _fail('vault must be initialized in this directory before proceeding.' + 
                '\n\n\tuse python vault.py init')
    
def _ask_for_password():
    password = getpass.getpass()
    while True:
        if _password_matches_initialization(password):
            break
        else:
            print('incorrect password.')
            password = getpass.getpass()
    return password
    
    
def _hash(pw):
    hashGen = hashlib.sha512()
    pw = pw.encode('utf-8')
    hashGen.update(pw)
    return hashGen.hexdigest()
    
def _password_matches_initialization(password):
    try:
        with open(DATA_FILENAME) as data_file:    
            data = json.load(data_file)
            expected_hash = data['pw_hash']
            given_hash = _hash(password)
            return expected_hash == given_hash
    except EnvironmentError:
        _fail('Error while accessing %d' % DATA_FILENAME)
    
def _is_initted():
     return os.path.isfile(DATA_FILENAME)
            
def _new_password_is_valid(password, password_confirm):
    if password != password_confirm:
        print('Passwords do not match!')
        return False
    elif len(password) == 0:
        print('Password must not be empty!')
        return False
    return True
    
def _ask_for_user_confirm_on_targets(targets, action):
    """asks the user to user to verify targeted files are correct."""
    if len(targets) == 0:
        _fail('There is nothing to %s.' % action)
    else:
        print('Targets:')
        print('\n'.join(['\t' + x for x in targets]) + '\n')
        answer = ''
        while answer != 'y' and answer != 'n':
            answer = input('%s %d files? (y/n): ' % (action, len(targets)))
        
        if answer != 'y':
            _fail('User cancelled procedure.')    
    
def _get_targets(local_path):
    if os.path.exists(local_path):
        return _get_nested_files_in_directory(local_path)  
    else:
        _fail('Cannot access %s: No such file or directory.' % local_path)

def _get_nested_files_in_directory(rootdir):
    fileList = []
    for root, subFolders, files in os.walk(rootdir):
        for file in files:
            fileList.append(os.path.join(root,file))
    return fileList
    
def _fail(message):
    if TESTING_MODE:
        raise Exception(message)
    else:
        print(message)
        sys.exit()
    
COMMANDS = {
    'encrypt': encrypt,
    'decrypt': decrypt,
    'init':    init,
    'status':  status,
    HELP_FLAG: help
}

if sys.version_info[0] < 3:
    raise 'Must be using python 3'

if __name__ == '__main__':
    args = list(sys.argv)
    if len(args) != 2:
        problem = 'Too many' if len(args) > 2 else 'Not enough'
        _fail('%s arguments given. ' + 
                'Use %s for more information.' % (problem, HELP_FLAG))
    
    command = args[1]

    if command in COMMANDS:
        COMMANDS[command]()
    else:
        _fail('Unrecognized command: %s' % command)
        
        
    
    
    
        
    
    

    


