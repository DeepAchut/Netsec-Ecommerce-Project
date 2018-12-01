'''
Created on 06-Nov-2018

@author: deepk
'''
import datetime
import random
import socket

from AESCipher import decryptAESData
from AESCipher import sendAESData
from HashGenerator import getHash
from RSAencryption import decryptMsg
from RSAencryption import sendData
from diffiehellman import getSessionKey, getDHkey
from signature import verifySign
import threadCustom


prDHkey = random.randint(100,1000)

def exchangeUserRSAPbKey(server,key):
    senderkey = ""
    try:
        server.send(key + ";" + getHash(key))
        temp = server.recv(1024)
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
        temp = server.recv(1024)
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

def onUserConnect(client,userBrokerSessionKey, userPbKey, pukey, prkey):
    brokerFlag = True
    while brokerFlag:
        sellerFlag = True
        ipadd = decryptAESData(client.recv(1024), userBrokerSessionKey)
        #DH Authentication Successful and Now can transmit messages
        #Now get Seller Ip address from the user and connect to the Seller
        print ipadd
        server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        port = int(ipadd.split(":")[1])
        server.connect((ipadd.split(":")[0],port))
        server.send("Broker")
        sellerPbKey = exchangeSellerRSAPbKey(server, pukey)
        print "Seller Pb Key received"
        print sellerPbKey
        if sellerPbKey:
            #Diffie-Hellman Key Exchange Starts here
            sendData(getDHkey(prDHkey), server, sellerPbKey)
            print "Broker - Seller Key Exchange successful"
            print "DH exchange starts"
            data = decryptMsg(server.recv(1024), prkey)
            sellerNounce = getHash(getSessionKey(data, prDHkey))
            print "DH Authentication successful"
            client.send(sellerPbKey)
            #client.send(sellerPbKey)
            userSellerPbKey = client.recv(1024)
            server.send(userSellerPbKey)
            print userSellerPbKey
            sellerDhKey = server.recv(2048)
            client.send(sellerDhKey)
            userDhkey = client.recv(1024)
            server.send(userDhkey)
            while sellerFlag:
                broucher = server.recv(1024)
                client.send(broucher)
                userinp = client.recv(1024)
                server.send(userinp)
                price = server.recv(1024)
                client.send(price)
                data = decryptAESData(client.recv(2048), userBrokerSessionKey)
                dbTransact = data.split("~")[0]
                sign = data.split("~")[1]
                date = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                if "No Purchase" not in data and verifySign(dbTransact, userPbKey, sign):
                    print "User authenticated Seller"
                    price = dbTransact.split(";")[0]
                    if price:
                        confFile = open("paymentDB/payment.csv", "a")
                        data = str(getHash(pukey)+";"+dbTransact+";"+date+";"+sign+";"+sellerPbKey)
                        confFile.write(data.replace(";",","))
                        confFile.write("\n")
                        confFile.close()                                            
                        sendAESData("Paid "+str(price), server, sellerNounce)
                        size = server.recv(1024)
                        client.send(size)
                        data = client.recv(1024)
                        server.send(data)
                        img = server.recv(40960000)
                        client.send(img)
                        repeatq = server.recv(1024)
                        client.send(repeatq)
                        data = decryptAESData(client.recv(2048), userBrokerSessionKey)
                        sendAESData(data.split(":B")[1], server, sellerNounce)
                        print data.split(":B")[0]
                        if data.split(":B")[0] == "broker":
                            print "Ending connection with seller"
                            sellerFlag = False
                        elif data.split(":B")[0] == "quit":
                            sellerFlag = False
                            brokerFlag = False
                        else:
                            print "Continuing connection with seller"
                else:
                    print "Purchase Aborted."
                    server.close()
                    client.close()
    return None

class Broker:
    def __init__(self):
        try:
            pukeyFile = open('Broker/public_key.pem', 'rb')
            prkeyFile = open('Broker/private_key.pem', 'rb')
            self.pukey = pukeyFile.read()
            self.prkey = prkeyFile.read()
            pukeyFile.close()
            prkeyFile.close()
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            port = int(raw_input("Enter port to start broker server: "))
            server.bind(('',port))
            print "socket binded to %s" %(port)
            threads = []
            while True:
                server.listen(4)
                print "socket is listening"
                # Establish connection with client. 
                client, addr = server.accept()
                print 'Got connection from', addr
                clienttype = client.recv(4096)
                print clienttype
                if clienttype == "User":
                    clienttype = ""
                    print "User Connected"
                    userPbKey = exchangeUserRSAPbKey(client, self.pukey)
                    if userPbKey:
                        #Diffie-Hellman Key Exchange Starts here
                        data = decryptMsg(client.recv(1024), self.prkey)
                        sendData(getDHkey(prDHkey), client, userPbKey)
                        userBrokerSessionKey = getSessionKey(data, prDHkey)
                        userBrokerSessionKey = getHash(userBrokerSessionKey)
                        twrv = threadCustom.CustomThread(target=onUserConnect, args=(client, userBrokerSessionKey, userPbKey, self.pukey, self.prkey))
                        twrv.start()
                        threads.append(twrv)
            for t in threads: 
                t.join() 
        except Exception as e:
            client.close()