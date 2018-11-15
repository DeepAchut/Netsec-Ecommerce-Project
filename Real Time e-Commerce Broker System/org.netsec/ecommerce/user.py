'''
Created on 06-Nov-2018

@author: deepk
'''

import random
import socket

from HashGenerator import getHash
from RSAencryption import sendData, generateRSAkey, decryptMsg
from diffiehellman import getDHkey
from diffiehellman import getSessionKey


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
            self.prDHKey = random.randint(5,10)
            self.sessionKey = ""
            #Setting up socket
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            server.connect((ip,port))
            server.send("User")
            brokerPbKey = exchangePublicKey(server, self.pukey)
            if brokerPbKey:
                print "User - Broker Key exchange successful"
                #Diffie-Hellman Key Exchange Starts here
                sendData(getDHkey(self.prDHKey), server, brokerPbKey)
                data = decryptMsg(server.recv(1024), key)
                nounce = getSessionKey(data, self.prDHKey)
                sendData(getHash(nounce), server, brokerPbKey)
                ack = decryptMsg(server.recv(1024), key)
                if ack == "ACK":
                    print "DH Authentication successful"
                    inp = raw_input("Enter the Seller IP address: ")
                    sendData(inp, server, brokerPbKey)
                else:
                    sendData("Error", server, brokerPbKey)
            else:
                print "Improper Broker Public key"
                server.close()
        except Exception as e:
            print e
            server.close()