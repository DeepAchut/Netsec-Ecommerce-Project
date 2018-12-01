'''
Created on 13-Nov-2018

@author: deepk
'''
import base64
import random
import socket
import thread
import time

from Crypto.PublicKey import RSA

from AESCipher import sendAESData, decryptAESData
from HashGenerator import getHash
from RSAencryption import decryptMsg
from RSAencryption import sendData
from diffiehellman import getSessionKey, getDHkey
import threadCustom


def exchangeRSAPbKey(server,key):
    senderkey = ""
    try:
        server.send(key + ";" + getHash(key))
        temp = server.recv(1024)
        if temp != "":
            print "Broker Pb Key + hash received from User"
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

def onBrokerConnect(client,pukey,prkey):
    repeatFlag = True
    try:
        brokerPbKey = exchangeRSAPbKey(client, pukey)
        prDHkey = random.randint(100,1000)
        if brokerPbKey:
            print "Received Broker Public key"
            #Diffie-Hellman Key Exchange Starts here
            data = decryptMsg(client.recv(1024), prkey)
            print data
            sendData(getDHkey(prDHkey), client, brokerPbKey)
            brokerSessionkey = getHash(getSessionKey(data, prDHkey))
            print brokerSessionkey
            print "DH Authentication successful"
            userEphemeralkey = client.recv(1024)
            #userEphemeralkey = client.recv(1024)
            prDHkey = random.randint(100,1000)
            sendData(getDHkey(prDHkey), client, userEphemeralkey)
            data = decryptMsg(client.recv(2048), prkey)
            userSessionKey = getHash(getSessionKey(data, prDHkey))
            print "Seller DH key received"
            broucher = """Below are the paintings available to buy
                Sr no.            Model                     Price
                1)                Mona Lisa                 $970
                2)                The Starry Night          $880
                3)                The Night Watch           $920
                4)                Impression, Sunrise       $810"""
            while repeatFlag:
                sendAESData(broucher, client, userSessionKey)
                userinp = decryptAESData(client.recv(1024), userSessionKey)
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
                sendAESData(str(price), client, userSessionKey)
                data = decryptAESData(client.recv(1024), brokerSessionkey)
                if ("Paid "+str(price)) in data:
                    jpgdata = ''
                    inf = open('sellerImg/'+str(userinp)+'.jpg', 'rb')
                    jpgdata = base64.b64encode(inf.read())
                    size = len(jpgdata)
                    sendAESData("SIZE %s" % size, client, userSessionKey)
                    ackSize = decryptAESData(client.recv(1024), userSessionKey)
                    if str(ackSize) == "GOT SIZE":
                        sendAESData(jpgdata, client, userSessionKey)
                    inf.close()
                    time.sleep(0.2)
                    sendAESData("Do you want to continue shopping?", client, userSessionKey)
                    data = decryptAESData(client.recv(2048), brokerSessionkey)
                    data = RSA.importKey(prkey).decrypt(eval(data))
                    if data == "N":
                        repeatFlag = False
                        print "Closing connection"
                        client.close()
                else:
                    print "Transaction Aborted"
    except Exception as e:
        client.close()
        print "Unable to process user message in Seller"
        print e  
    return None

class Seller:
    def __init__(self):
        try:
            pukeyFile = open('Seller/public_key.pem', 'rb')
            prkeyFile = open('Seller/private_key.pem', 'rb')
            self.pukey = pukeyFile.read()
            self.prkey = prkeyFile.read()
            pukeyFile.close()
            prkeyFile.close()
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
                    onBrokerConnect(client,self.pukey,self.prkey)
                    server.close()
                else:
                    print "Unidentified Client type"
                    client.close()
        except Exception as e:
            client.close()