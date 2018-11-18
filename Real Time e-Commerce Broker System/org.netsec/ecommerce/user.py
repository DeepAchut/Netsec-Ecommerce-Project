'''
Created on 06-Nov-2018

@author: deepk
'''

import datetime
import random
import socket
import time

from AESCipher import AESCipher
from AESsignature import signData
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
            prDHKey = random.randint(100,1000)
            self.sessionKey = ""
            #Setting up socket
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            server.connect((ip,int(port)))
            server.send("User")
            brokerPbKey = exchangePublicKey(server, self.pukey)
            if brokerPbKey:
                print "User - Broker Key exchange successful"
                #Diffie-Hellman Key Exchange Starts here
                sendData(getDHkey(prDHKey), server, brokerPbKey)
                data = decryptMsg(server.recv(1024), key)
                brokerSessionKey = getSessionKey(data, prDHKey)
                sendData(getHash(brokerSessionKey), server, brokerPbKey)
                ack = decryptMsg(server.recv(1024), key)
                if ack == "ACK":
                    print "DH Authentication successful"
                    inp = raw_input("Enter the Seller IP address & port (format:-ipaddress:port): ")
                    sendData(inp, server, brokerPbKey)
                    sellerPbKey = ""
                    sellerPbKey = server.recv(2048)
                    print "Received Seller key in User"
                    print sellerPbKey
                    server.send("ACK")
                    prDHKey = random.randint(100,1000)
                    sendData(getDHkey(prDHKey), server, sellerPbKey)
                    sellerNounce = decryptMsg(server.recv(2048), key)
                    nounce = getSessionKey(sellerNounce.split("~")[0], prDHKey)
                    if getHash(nounce) == sellerNounce.split("~")[1]:
                        data = AESCipher(nounce).encrypt("NOUNCE VERIFIED")
                        server.send(data)
                        data = server.recv(2048)
                        broucher = AESCipher(nounce).decrypt(data)
                        print broucher
                        inp = raw_input("Press the number to select any product: ")
                        data = AESCipher(nounce).encrypt(inp)
                        server.send(data)
                        data = server.recv(1024)
                        price = AESCipher(nounce).decrypt(data)
                        sellerId = price.split(";")[1]
                        price = price.split(";")[0]
                        print "Price of the product you want to buy is $" + str(price)
                        time.sleep(0.5)
                        inp = raw_input("Are you sure you want to buy? [Y/N]: ")
                        date = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                        dbTransact = str(self.id+";"+price+";"+sellerId+";"+date)
                        sign = signData(dbTransact, self.prkey)
                        if inp == "Y":
                            data = AESCipher(getHash(brokerSessionKey)).encrypt(dbTransact+"~"+sign)
                            server.send(data)
                            data = server.recv(2048)
                            imgSize = AESCipher(nounce).decrypt(data)
                            print imgSize
                            if imgSize.startswith('SIZE'):
                                tmp = imgSize.split()
                                size = int(tmp[1])
                                print 'got size'
                                print 'size is %s' % size
                                data = AESCipher(nounce).encrypt("GOT SIZE")
                                server.send(data)
                                imgData = server.recv(40960000)
                                imageString = AESCipher(nounce).decrypt(imgData)
                                output_file = open("Output/output_"+self.id+".jpg", "wb")
                                output_file.write(imageString.decode('base64'))
                                output_file.close()
                                server.close()
                            else:
                                print "Error in getting image size"
                                server.close()
                        else:
                            sendData("No Purchase", server, key)
                    else:
                        data = AESCipher(nounce).encrypt("NOUNCE MISMATCH")
                        server.send(data)
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