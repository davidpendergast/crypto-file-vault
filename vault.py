from cryptography.fernet import Fernet

import sys
import os.path
import re
import getpass
import hashlib
import json
import random

'''if true, exceptions are raised on failure instead of exiting.'''
TESTING_MODE = False

THIS_FILENAME = None
HELP_FLAG = '--help'

DATA_FILENAME = 'vaultdata.json'

PROTECTED = ['.*vault\.py', '.*vaultdata\.json', '.*README.txt', '.*\.git.*']
    
def encrypt(args):
    targets, password = _verify_targets_and_password(args, 'encrypt')
    do_encryption(targets, password)
    
def do_encryption(targets, password):
    password_hash = _hash(password)
    for target in targets:
        if is_encrypted(target):
            print('Skipping already encrypted file: %s' % target)
        else:
            try:
                with open(target, 'rb') as data_file:
                    raw_data = data_file.read()
                    as_ints = [int(x) for x in raw_data]
                    json_blob = {
                        'file_name':target,
                        'file_contents':as_ints
                    }
                    crypto_data = _encrypt_data(json_blob, password)
                    actual_json = {
                        'pw_hash':password_hash,
                        'crypto_data':crypto_data
                    }
                    #TODO make this safe
                    filename = 'secret'+str(random.randint(0,999999999))+'.json'
                    with open(filename, 'w') as out_file:
                        json.dump(actual_json, out_file, indent=4)
            
            except Exception as e:
                print('Exception thrown while encrypting file: %s' % target)
                raise e

def decrypt(args):
    targets, password = _verify_targets_and_password(args, 'decrypt')
    do_decryption(targets, password)
    
def do_decryption(targets, password):
    password_hash = _hash(password)
    for target in targets:
        if not is_encrypted(target):
            print('Skipping non-encrypted file: %s' % target)
        else:
            try:
                with open(target, 'r') as data_file:    
                    json_blob = json.load(data_file)
                    if password_hash != json_blob['pw_hash']:
                        print('File encrypted with different initialization: %s' % target)
                    crypto_data = json_blob['crypto_data'] 
                    print('Decrypting %s...' % target)
                    raw_data = _decrypt_data(crypto_data, password)
                    print(raw_data)
                    file_name = raw_data['file_name']
                    file_contents = raw_data['file_contents']
                    as_bytes = bytes(file_contents)
                    write_file(file_name, as_bytes)
                
                os.remove(target)
                    
            except Exception as e:
                print('Exception thrown while reading file: %s' % target)
                print(e)
              
def _decrypt_data(crypto_data, password):
    # TODO - crypto_data -> json string
    json_string = crypto_data
    return json.loads(json_string)
    
def _encrypt_data(json_data, password):
    json_string = json.dumps(json_data) 
    # TODO - json_string -> crypto_data
    crypto_data = json_string
    return crypto_data
    
def write_file(file_name, file_contents):
    with open(file_name,'wb') as f:
        f.write(file_contents)
                    
def is_encrypted(target):
    '''returns true if target filename is already encrypted.'''
    try:
        with open(target) as data_file:    
            data = json.load(data_file)
            return 'pw_hash' in data and 'crypto_data' in data
    except:
        return False
    
def _verify_targets_and_password(args, action):
    if not _is_initted():
        _fail('vault must be initted in this directory before proceeding.' + 
                '\n\n\tuse python vault.py init')
    targets = _get_targets(args)
    _verify_targets(targets, action)
    password = getpass.getpass()
    while True:
        if _password_matches_initialization(password):
            break
        else:
            print('incorrect password.')
            password = getpass.getpass()
    return (targets, password)
    
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
    
def init(args):
    if _is_initted():
        _fail('vault is already initialized in this directory.')
    
    print('Enter a new encrypt/decrypt password twice:')
    
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

def help(args):
    print('called help')
    
def _verify_targets(targets, action):
    """asks the user to user to verify targeted files are correct."""
    if len(targets) == 0:
        _fail('There is nothing to encrypt/decrypt.')
    else:
        print('Targets:')
        print('\n'.join(['\t' + x for x in targets]) + '\n')
        answer = ''
        while answer != 'y' and answer != 'n':
            answer = input('%s %d files? (y/n): ' % (action, len(targets)))
        
        if answer != 'y':
            _fail('User cancelled procedure.')       
    
def _get_targets(args):
    '''returns a list of filenames'''
    targets = []
    if len(args) == 0:
        target = os.path.dirname(os.path.realpath(__file__))
        targets = _get_nested_files_in_directory(target)
    elif len(args) == 1:
        if os.path.exists(args[0]):
            if os.path.isfile(args[0]):
                targets = list(args[0])
            else:
                targets = _get_nested_files_in_directory(args[0])
        else:
            _fail('Cannot access %s: No such file or directory.' % args[0])
    else:
        print(args)
        _fail('Too many arguments given. ' + 
                'Use %s for more information.' % HELP_FLAG)
    
    return _filter_protected(targets)
    
def _filter_protected(targets):
    regex = '|'.join([x + '\Z' for x in PROTECTED])
    pattern = re.compile(regex)
    filtered_targets = [x for x in targets if not pattern.match(x)]
    return filtered_targets

def _get_nested_files_in_directory(rootdir):
    fileList = []
    for root, subFolders, files in os.walk(rootdir):
        for file in files:
            fileList.append(os.path.join(root,file))
    return fileList
    
def _fail(message):
    if TESTING_MODE:
        raise Exception()
    else:
        print(message)
        sys.exit()
    
COMMANDS = {
    'encrypt': encrypt,
    'decrypt': decrypt,
    'init' : init,
    HELP_FLAG: help
}

if __name__ == '__main__':
    args = list(sys.argv)
    if len(args) < 2:
        _fail('Not enough arguments given. ' + 
                'Use %s for more information.' % HELP_FLAG)
    THIS_FILE_NAME = args.pop(0)
    command = args.pop(0)

    if command in COMMANDS:
        COMMANDS[command](args)
    else:
        _fail('Unrecognized command: %s' % command)
        
        
    
    
    
        
    
    

    


