'''
Created on 13-Nov-2018

@author: deepk
'''
import random
import socket
import thread

from HashGenerator import getHash
from RSAencryption import generateRSAkey, decryptMsg
from RSAencryption import sendData
from diffiehellman import getSessionKey, getDHkey

prDHkey = random.randint(2,6)

def exchangeRSAPbKey(server,key):
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
                print "Broker public key hash recieved by Seller"
                print data
                senderkey = data
            else:
                print "Sender Pb key doesn't match it's hash"
    except Exception as e:
        print "Unable to get broker public key"
        print e
    return senderkey

def onBrokerConnect(client,addr):
    try:
        key = generateRSAkey()
        pukey = key.publickey().exportKey()
        brokerPbKey = exchangeRSAPbKey(client, pukey)
        if brokerPbKey:
            print "Received Seller Public key"
            #Diffie-Hellman Key Exchange Starts here
            data = decryptMsg(client.recv(1024), key)
            sendData(getDHkey(prDHkey), client, brokerPbKey)
            nounceHash = getHash(getSessionKey(data, prDHkey))
            userNounceHash = decryptMsg(client.recv(1024), key)
            if userNounceHash == nounceHash:
                sendData("ACK", client, brokerPbKey)
                data = decryptMsg(client.recv(1024), key)
                if "Error" not in data:
                    #DH Authentication Successful and Now can transmit messages
                    print data
                    print "Reached End"
                else:
                    print "Nounce didn't match between user and brokers"
            else:
                print "Nounce exchange failed"          
    except Exception as e:
        print "Unable to process user message in broker"
        print e  
    return None

class Seller:
    def __init__(self):
        try:
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            port = 55553
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
                if clienttype == "Broker":
                    print "Broker Connected"
                    thread.start_new_thread(onBrokerConnect(client,addr))
                else:
                    print "Unidentified Client type"
                    client.close()
        except Exception as e:
            print e
            print "Unable to start server. Check Server Address or Port"