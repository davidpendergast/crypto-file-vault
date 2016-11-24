
import sys
import os.path
import re

THIS_FILENAME = None
HELP_FLAG = '--help'

PROTECTED = ['.*vault\.py', '.*\.git.*']
    
def encrypt(args):
    targets = _get_targets(args)
    print('Targets:')
    print('\n\t'.join(targets))

def decrypt(args):
    targets = _get_targets(args)
    print('Targets:')
    print('\n\t'.join(targets))
    
def init(args):
    pass
    
def help(args):
    print('called help')
    
def _get_targets(args):
    '''returns a list of filenames'''
    targets = []
    if len(args) == 0:
        target = os.path.dirname(os.path.realpath(__file__))
        targets = _get_nested_files_in_directory(target)
    elif len(args) == 1:
        if os.path.isfile(args[0]):
            targets = list(args[0])
        else:
            targets = _get_nested_files_in_directory(args[0])
    else:
        _invalid_arguments('Too many arguments given. ' + 
                'Use %s for more information.' % HELP_FLAG)
    
    return _filter_protected(targets)
    
def _filter_protected(targets):
    regex = '|'.join([x + '\Z' for x in PROTECTED])
    pattern = re.compile(regex)
    filtered_targets = [x for x in targets if not pattern.match(x)]
    # print('Targets:\n %s' % '\n    '.join(targets))
    # print('Filtered targets %s:\n %s' % (regex, '\n    '.join(filtered_targets)))
    return filtered_targets

def _get_nested_files_in_directory(rootdir):
    fileList = []
    for root, subFolders, files in os.walk(rootdir):
        for file in files:
            fileList.append(os.path.join(root,file))
    return fileList
    
def _fetch_all_target_filenames(target):
    if not os.path.exists(target):
        _invalid_arguments('Cannot access %s: No such file or directory.' % target)

def _invalid_arguments(message):
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
        _invalid_arguments('Not enough arguments given. ' + 
                'Use %s for more information.' % HELP_FLAG)
    THIS_FILE_NAME = args.pop(0)
    command = args.pop(0)

    if command in COMMANDS:
        COMMANDS[command](args)
    else:
        _invalid_arguments('Unrecognized command: %s' % command)
        
        
    
    
    
        
    
    

    


