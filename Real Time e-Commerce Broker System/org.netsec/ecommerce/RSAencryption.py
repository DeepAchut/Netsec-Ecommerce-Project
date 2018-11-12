'''
Created on 11-Nov-2018

@author: deepk
'''
from Crypto import Random
from Crypto.PublicKey import RSA

from HashGenerator import getHash


def generateRSAkey():
    random_generator = Random.new().read
    return RSA.generate(1024,random_generator)

def decryptMsg(msg, key):
    data = ""
    try:
        if verifyMsg(msg, key):
            en = eval(msg)
            decrypt = key.decrypt(en)
            data = decrypt.split(";")[0]
    except Exception as e:
        print "Unable to decrypt message"
        print e        
    return data

def verifyMsg(msg, key):
    flag = False
    en = eval(msg)
    decrypt = key.decrypt(en)
    data = decrypt.split(";")[0]
    hash = decrypt.split(";")[1]
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
        server.send(str(dataToSend))
        flag = True
    except Exception as e:
        print "Unable to send data"
        print e
    return flag
