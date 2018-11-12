'''
Created on 06-Nov-2018

@author: deepk
'''

import random
import socket

from HashGenerator import getHash
from RSAencryption import sendData, generateRSAkey


def exchangePublicKey(server, userPbKey):
    key = ""
    try:
        brokerPbKey = server.recv(2048)
        server.send(userPbKey)
        if brokerPbKey != "":
            print "Broker Pb Key"
            print brokerPbKey
            ack = server.recv(1024)
            server.send("ACK")
            if ack == "ACK":
                brokerPbKeyHash = server.recv(1024)
                server.send(getHash(userPbKey))
                print ("Broker public key hash in User"+brokerPbKeyHash)
                if brokerPbKeyHash == getHash(brokerPbKey):
                    key = brokerPbKey
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
            while True:
                server.send("User")
                brokerPbKey = exchangePublicKey(server, self.pukey)
                if brokerPbKey:
                    print "User - Broker Key exchange successful"
                    inp = raw_input("Enter the Seller IP address & port (format: ipaddress:port): ")
                    if sendData(inp, server, brokerPbKey):
                        print "Connecting Seller"
                else:
                    print "Improper Broker Public key"
                    break
        except Exception as e:
            print e                    