from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os, sys

def main(args):
    key = RSA.import_key(open("private.pem").read())
    crypt = PKCS1_OAEP.new(key)
    file_path= args[0]
    with open(file_path, "rb") as f:
        enc_fern = f.read()
    os.remove(file_path)
    name = file_path[:-12] + "use_me.btkt"
    dec_fern = crypt.decrypt(enc_fern)
    with open(name, "wb") as f:
        f.write(dec_fern)
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("USAGE: python3 decrypt_fernkey.py [FILE_TO_DECRYPT] (file must be in the same directory as script)")
    else:
        main(sys.argv[1:])