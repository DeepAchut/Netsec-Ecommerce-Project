'''
Created on 11-Nov-2018

@author: deepk
'''
from base64 import b64encode, b64decode

from Crypto import Random
from Crypto.PublicKey import RSA

from HashGenerator import getHash


def generateRSAkey():
    random_generator = Random.new().read
    return RSA.generate(2048,random_generator)

def decryptMsg(msg, key):
    rdata = ""
    try:
        prkey = RSA.importKey(key)
        en = eval(b64decode(msg))
        decrypt = prkey.decrypt(en)
        data = decrypt.split(";")[0]
        hash = decrypt.split(";")[1]
        if verifyMsg(data, hash):
            rdata = data
    except Exception as e:
        print "Unable to decrypt RSA encrypted message"
        print e        
    return rdata

def verifyMsg(data, hash):
    flag = False
    if hash == getHash(data):
        flag = True
    else:
        flag = False
    return flag

def sendData(msg, server, key):
    pukey = RSA.importKey(key)
    flag = False
    try:
        dataToSend = pukey.encrypt((str(msg) + ";" + str(getHash(str(msg)))),32)
        server.send(b64encode(str(dataToSend)))
        flag = True
    except Exception as e:
        print "Unable to send RSA encrypted data"
        print e
    return flag
