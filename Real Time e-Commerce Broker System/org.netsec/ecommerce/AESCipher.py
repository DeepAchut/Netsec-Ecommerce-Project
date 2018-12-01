from base64 import b64decode
from base64 import b64encode
from hashlib import md5
import random

from Crypto import Random
from Crypto.Cipher import AES

from HashGenerator import getHash


# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def sendAESData(msg, server, nounce):
    rand = random.randint(1,10)
    try:
        hash = getHash(msg+str(rand))
        data = str(msg) + ";" + str(hash) + "~RND~" + str(rand)
        encrypt = AESCipher(nounce).encrypt(data)
        server.send(encrypt)
    except Exception as e:
        print "Unable to send AES encrypted data"
        print e
    return 0

def verifyMsg(data, hash, rand):
    flag = False
    if hash == getHash(data + rand):
        flag = True
    else:
        flag = False
    return flag

def decryptAESData(msg, nounce):
    rdata = ""
    try:
        decrypt = AESCipher(nounce).decrypt(str(msg))
        rand = decrypt.split("~RND~")[1]
        decrypt = decrypt.split("~RND~")[0]
        data = decrypt.split(";")[0]
        hash = decrypt.split(";")[1]
        if verifyMsg(data, hash, rand):
            rdata = data
    except Exception as e:
        print "Unable to decrypt AES encrypted message"
        print e        
    return rdata

class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1.
    """

    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:])).decode('utf8')