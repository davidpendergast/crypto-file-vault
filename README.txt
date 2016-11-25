
Setup:

    1.  get python 3
    2.  install cryptography: https://cryptography.io/en/latest/installation/
    
Usage:

    1.  Run the following command, and choose a password when prompted:
        
            python vault.py init
        
        This will create a new file named 'vaultdata.json', and two empty
        directories named 'plain_files' and 'secret_files'. Do not rename any
        of these items.
        
    2.  Place desired files for encryption into 'plain_files', and run the
        command:

            python vault.py encrypt
        
        The program will display which files will be encrypted, and ask for
        verification. After accepting the files, supply the password to start
        the encryption process.
        
        When it finishes, the files in 'plain_files' will be removed, and new
        encrypted files should appear in 'secret_files.' 
        
    3.  Use the status command at any time to see a list of non-encrypted and 
        encrypted files in the system:
        
            python vault.py status
            
    4.  To decrypt, run the command:
        
            python vault.py decrypt
            
        This will launch a process similar to encryption that results in 
        the secret files being decrypted and placed back into 'plain_files'.
    
