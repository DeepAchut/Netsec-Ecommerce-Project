'''
Created on 13-Nov-2018

@author: deepk
'''
import base64
import random
import socket
import thread
import time

from AESCipher import AESCipher
from HashGenerator import getHash
from RSAencryption import generateRSAkey, decryptMsg
from RSAencryption import sendData
from diffiehellman import getSessionKey, getDHkey


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

def onBrokerConnect(client,addr,sellerId):
    try:
        key = generateRSAkey()
        pukey = key.publickey().exportKey()
        brokerPbKey = exchangeRSAPbKey(client, pukey)
        prDHkey = random.randint(100,1000)
        if brokerPbKey:
            print "Received Seller Public key"
            #Diffie-Hellman Key Exchange Starts here
            data = decryptMsg(client.recv(1024), key)
            sendData(getDHkey(prDHkey), client, brokerPbKey)
            nounceHash = getHash(getSessionKey(data, prDHkey))
            brokerNounceHash = decryptMsg(client.recv(1024), key)
            if brokerNounceHash == nounceHash:
                sendData("ACK", client, brokerPbKey)
                data = client.recv(2048)
                if data and "Error" not in data:
                    #DH Authentication Successful and Now can transmit messages
                    userPbKey = data
                    print "Received User key in Seller"
                    print userPbKey
                    client.send("ACK")
                    data = decryptMsg(client.recv(1024), key)
                    prDHkey = random.randint(5,10)
                    sessionKey = getSessionKey(data, prDHkey)
                    nounceHash = getHash(sessionKey)
                    sendData(str(getDHkey(prDHkey))+"~"+str(nounceHash), client, userPbKey)
                    data = client.recv(1024)
                    ack = AESCipher(sessionKey).decrypt(data)
                    if ack == "NOUNCE VERIFIED":
                        print "Seller Authentication by User completed"
                        broucher = """Below are the paintings available to buy
                            Sr no.            Model                     Price
                            1)                Mona Lisa                 $970
                            2)                The Starry Night          $880
                            3)                The Night Watch           $920
                            4)                Impression, Sunrise       $810"""
                        encryptMsg = AESCipher(sessionKey).encrypt(broucher)
                        client.send(encryptMsg)
                        data = client.recv(1024)
                        userinp = AESCipher(sessionKey).decrypt(data)
                        userinp = int(userinp)
                        price = 0
                        if userinp == 1:
                            price = 970
                        elif userinp == 2:
                            price = 880
                        elif userinp == 3:
                            price = 920
                        elif userinp == 4:
                            price = 810
                        data = AESCipher(sessionKey).encrypt(str(price)+";"+str(sellerId))
                        client.send(data)
                        data = decryptMsg(client.recv(1024), key)
                        if ("Paid "+str(price)) in data:
                            jpgdata = ''
                            inf = open('sellerImg/'+str(userinp)+'.jpg', 'rb')
                            jpgdata = base64.b64encode(inf.read())
                            size = len(jpgdata)
                            client.send(AESCipher(sessionKey).encrypt("SIZE %s" % size))
                            ackSize = AESCipher(sessionKey).decrypt(client.recv(1024))
                            if str(ackSize) == "GOT SIZE":
                                encryptMsg = AESCipher(sessionKey).encrypt(jpgdata)
                                client.send(encryptMsg)
                            inf.close()
                            client.close()
                        else:
                            print "Transaction Aborted"
                            client.close()
                    else:
                        print "Seller Authentication by user failed"
                        client.close()
                else:
                    print "Nounce didn't match between user and brokers"
                    client.close()
            else:
                print "Nounce exchange failed"
                client.close()          
    except Exception as e:
        client.close()
        print "Unable to process user message in broker"
        print e  
    return None

class Seller:
    def __init__(self, id):
        try:
            self.id = id
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            port = int(raw_input("Enter port to start seller server: "))
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
                    thread.start_new_thread(onBrokerConnect(client,addr, self.id))
                else:
                    print "Unidentified Client type"
                    client.close()
        except Exception as e:
            client.close()