'''
Created on 06-Nov-2018

@author: deepk
'''
import random
import socket
import thread
import time

from HashGenerator import getHash
from RSAencryption import generateRSAkey, decryptMsg
from RSAencryption import sendData
from diffiehellman import getSessionKey, getDHkey


prDHkey = random.randint(2,6)

def exchangeUserRSAPbKey(server,key):
    senderkey = ""
    try:
        server.send(key + ";" + getHash(key))
        temp = server.recv(2048)
        if temp != "":
            print "User Pb Key + hash received from User"
            print temp
            data = temp.split(";")[0]
            dataHash = temp.split(";")[1]
            if getHash(data) == dataHash:
                print "User RSA Public key is:"
                print data
                senderkey = data
            else:
                print "Sender Pb key doesn't match it's hash"
    except Exception as e:
        print "Unable to get broker public key"
        print e
    return senderkey

def exchangeSellerRSAPbKey(server,key):
    senderkey = ""
    try:
        temp = server.recv(2048)
        if temp != "":
            print "User Pb Key + hash received from User"
            print temp
            data = temp.split(";")[0]
            dataHash = temp.split(";")[1]
            if getHash(data) == dataHash:
                server.send(key + ";" + getHash(key))
                print "Seller public key hash recieved by Broker"
                senderkey = data
            else:
                print "Sender Pb key doesn't match it's hash"
    except Exception as e:
        print "Unable to get broker public key"
        print e
    return senderkey

def onUserConnect(client,addr):
    try:
        key = generateRSAkey()
        pukey = key.publickey().exportKey()
        userPbKey = exchangeUserRSAPbKey(client, pukey)
        if userPbKey:
            #Diffie-Hellman Key Exchange Starts here
            data = decryptMsg(client.recv(1024), key)
            sendData(getDHkey(prDHkey), client, userPbKey)
            nounceHash = getHash(getSessionKey(data, prDHkey))
            userNounceHash = decryptMsg(client.recv(1024), key)
            if userNounceHash == nounceHash:
                sendData("ACK", client, userPbKey)
                ipadd = decryptMsg(client.recv(1024), key)
                if "Error" not in data:
                    #DH Authentication Successful and Now can transmit messages
                    #Now get Seller Ip address from the user and connect to the Seller
                    print ipadd
                    try:
                        brokerRsaKey = generateRSAkey()
                        brokerPuKey = brokerRsaKey.publickey().exportKey()
                        server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        port = 55553
                        server.connect((ipadd,port))
                        server.send("Broker") 
                        sellerPbKey = exchangeSellerRSAPbKey(server, brokerPuKey)
                        if sellerPbKey:
                            #Diffie-Hellman Key Exchange Starts here
                            sendData(getDHkey(prDHkey), server, sellerPbKey)
                            print "Broker - Seller Key Exchange successful"
                            print "DH exchange starts"
                            data = decryptMsg(server.recv(1024), brokerRsaKey)
                            nounce = getSessionKey(data, prDHkey)
                            sendData(getHash(nounce), server, sellerPbKey)
                            ack = decryptMsg(server.recv(1024), brokerRsaKey)
                            if ack == "ACK":
                                print "DH Authentication successful"
                                sendData("Authentication done", server, sellerPbKey)
                            else:
                                sendData("Error", server, sellerPbKey)
                    except Exception as e:
                        print e
                        print "Unable to connect Seller. Check Seller Ip Address or Port"
                    
                else:
                    print "Nounce didn't match between user and brokers"
            else:
                print "Nounce exchange failed"          
    except Exception as e:
        print "Unable to process user message in broker"
        print e
    return None

class Broker:
    def __init__(self):
        try:
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            port = 55552
            server.bind(('',port))
            print "socket binded to %s" %(port)
            server.listen(5)
            print "socket is listening"
            while True:
                # Establish connection with client. 
                client, addr = server.accept()
                print 'Got connection from', addr
                clienttype = client.recv(1024)
                print clienttype
                if clienttype == "User":
                    print "User Connected"
                    thread.start_new_thread(onUserConnect(client,addr))
                else:
                    print "Unidentified Client type"
                    client.close()
        except Exception as e:
            print e
            print "Unable to start broker server. Check Server Address or Port"