'''
Created on 06-Nov-2018

@author: deepk
'''

import random
import socket
import time

from HashGenerator import getHash
from RSAencryption import sendData, generateRSAkey, decryptMsg
from diffiehellman import getDHkey
from diffiehellman import getSessionKey
from AESCipher import AESCipher


def exchangePublicKey(server, userPbKey):
    key = ""
    try:
        temp = server.recv(2048)
        if temp != "":
            print "Broker Pb Key + hash received from Broker"
            print temp
            data = temp.split(";")[0]
            dataHash = temp.split(";")[1]
            if getHash(data) == dataHash:
                server.send(userPbKey + ";" + getHash(userPbKey))
                print ("Broker public key hash recieved by User")
                key = data
            else:
                print "Broker Public Key Hash doesn't match"
    except Exception as e:
        print "Unable to get broker public key"
        print e
    return key
    
class User:
    def __init__(self,ip,port,userId):
        try:
            self.id = userId
            key = generateRSAkey()
            self.pukey = key.publickey().exportKey()
            self.prkey = key.exportKey()
            #generating DH keys
            prDHKey = random.randint(5,10)
            self.sessionKey = ""
            #Setting up socket
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            server.connect((ip,port))
            server.send("User")
            brokerPbKey = exchangePublicKey(server, self.pukey)
            if brokerPbKey:
                print "User - Broker Key exchange successful"
                #Diffie-Hellman Key Exchange Starts here
                sendData(getDHkey(prDHKey), server, brokerPbKey)
                data = decryptMsg(server.recv(1024), key)
                nounce = getSessionKey(data, prDHKey)
                sendData(getHash(nounce), server, brokerPbKey)
                ack = decryptMsg(server.recv(1024), key)
                if ack == "ACK":
                    print "DH Authentication successful"
                    inp = raw_input("Enter the Seller IP address: ")
                    sendData(inp, server, brokerPbKey)
                    sellerPbKey = ""
                    sellerPbKey = server.recv(2048)
                    print "Received Seller key in User"
                    print sellerPbKey
                    server.send("ACK")
                    prDHKey = random.randint(10,15)
                    sendData(getDHkey(prDHKey), server, sellerPbKey)
                    sellerNounce = decryptMsg(server.recv(2048), key)
                    nounce = getSessionKey(sellerNounce.split("~")[0], prDHKey)
                    if getHash(nounce) == sellerNounce.split("~")[1]:
                        data = server.recv(2048)
                        broucher = AESCipher(nounce).decrypt(data)
                        print broucher
                        inp = raw_input("Press the number to select any product: ")
                        data = AESCipher(nounce).encrypt(inp)
                        server.send(data)
                    else:
                        print "Unable to authenticate seller"
                        server.close()                
                else:
                    sendData("Error", server, brokerPbKey)
            else:
                print "Improper Broker Public key"
                server.close()
        except Exception as e:
            print e
            server.close()