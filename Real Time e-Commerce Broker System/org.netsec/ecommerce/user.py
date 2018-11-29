'''
Created on 06-Nov-2018

@author: deepk
'''

import datetime
import random
import socket
import time

from AESCipher import sendAESData, decryptAESData
from AESsignature import signData
from HashGenerator import getHash
from RSAencryption import sendData, generateRSAkey, decryptMsg
from diffiehellman import getDHkey
from diffiehellman import getSessionKey


def exchangePublicKey(server, userPbKey):
    key = ""
    try:
        temp = server.recv(1024)
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

def connectBroker(server, brokerSessionKey, pukey, prkey, brokerPbKey):
    inp = raw_input("Enter the Seller IP address & port (format:-ipaddress:port): ")
    sendAESData(inp, server, brokerSessionKey)
    sellerPbKey = server.recv(1024)
    print "Received Seller key in User"
    print sellerPbKey
    userSellerkey = generateRSAkey()
    userSellerPbkey = userSellerkey.publickey().exportKey()
    userSellerPrkey = userSellerkey.exportKey()
    #sendData(str(userSellerPbkey), server, sellerPbKey)
    server.send(userSellerPbkey)
    time.sleep(0.5)
    sellerNounce = decryptMsg(server.recv(2048), userSellerPrkey)
    prDHKey = random.randint(100,1000)
    sendData(getDHkey(prDHKey), server, sellerPbKey)
    sellerSessionKey = getHash(getSessionKey(sellerNounce, prDHKey))                    
    broucher = decryptAESData(server.recv(1024), sellerSessionKey)
    print broucher
    inp = raw_input("Press the number to select any product: ")
    sendAESData(inp, server, sellerSessionKey)
    price = decryptAESData(server.recv(1024), sellerSessionKey)
    print "Price of the product you want to buy is $" + str(price)
    inp = raw_input("Are you sure you want to buy? [Y/N]: ")
    dbTransact = str(price)
    sign = signData(dbTransact, prkey)
    if inp == "Y":
        sendAESData(dbTransact+"~"+sign, server, brokerSessionKey)
        imgSize = decryptAESData(server.recv(1024), sellerSessionKey)
        print imgSize
        if imgSize.startswith('SIZE'):
            tmp = imgSize.split()
            size = int(tmp[1])
            print 'got size'
            print 'size is %s' % size
            sendAESData("GOT SIZE", server, sellerSessionKey)
            imageString = decryptAESData(server.recv(40960000), sellerSessionKey)
            output_file = open("Output/output_buyer.jpg", "wb")
            output_file.write(imageString.decode('base64'))
            output_file.close()
            print "Transaction completed successfully. Hope to see you soon again"
        else:
            print "Error in getting image size"
            server.close()
    else:
        sendData("No Purchase", server, prkey)
    return None
    
class User:
    def __init__(self,ip,port):
        try:
            pukeyFile = open('User/public_key.pem', 'rb')
            prkeyFile = open('User/private_key.pem', 'rb')
            self.pukey = pukeyFile.read()
            self.prkey = prkeyFile.read()
            pukeyFile.close()
            prkeyFile.close()
            #generating DH keys
            prDHKey = random.randint(100,1000)
            #Setting up socket
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            server.connect((ip,int(port)))
            server.send("User")
            brokerPbKey = exchangePublicKey(server, self.pukey)
            if brokerPbKey:
                print "User - Broker Key exchange successful"
                #Diffie-Hellman Key Exchange Starts here
                sendData(getDHkey(prDHKey), server, brokerPbKey)
                data = decryptMsg(server.recv(1024), self.prkey)
                brokerSessionKey = getSessionKey(data, prDHKey)
                brokerSessionKey = getHash(brokerSessionKey)
                print "DH Authentication successful"    
                connectBroker(server, brokerSessionKey, self.pukey, self.prkey, brokerPbKey)
            else:
                print "Issue in broker key"
        except Exception as e:
            print e