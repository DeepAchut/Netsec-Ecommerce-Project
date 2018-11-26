'''
Created on 06-Nov-2018

@author: deepk
'''
import os
import random
import socket
import thread
import time

from AESCipher import AESCipher
from AESsignature import verifySign
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
            userBrokerNounce = getSessionKey(data, prDHkey)
            nounceHash = getHash(userBrokerNounce)
            userNounceHash = decryptMsg(client.recv(1024), key)
            if userNounceHash == nounceHash:
                sendData("ACK", client, userPbKey)
                ipadd = decryptMsg(client.recv(1024), key)
                if "Error" not in data:
                    #DH Authentication Successful and Now can transmit messages
                    #Now get Seller Ip address from the user and connect to the Seller
                    print ipadd
                    brokerRsaKey = generateRSAkey()
                    brokerPuKey = brokerRsaKey.publickey().exportKey()
                    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    port = int(ipadd.split(":")[1])
                    server.connect((ipadd.split(":")[0],port))
                    server.send("Broker") 
                    sellerPbKey = exchangeSellerRSAPbKey(server, brokerPuKey)
                    print "Seller Pb Key received"
                    print sellerPbKey
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
                            server.send(userPbKey)
                            client.send(sellerPbKey)
                            ackUser = client.recv(3)
                            ackSeller = server.recv(1024)
                            print ackSeller
                            print ackUser
                            if ackUser == "ACK" and ackSeller == "ACK":
                                data = client.recv(1024)
                                server.send(data)
                                print "Nounce exchange in Process between Seller and User"
                                data = server.recv(2048)
                                client.send(data)
                                ack = client.recv(1024)
                                server.send(ack)
                                broucher = server.recv(2048)
                                client.send(broucher)
                                userinp = client.recv(1024)
                                server.send(userinp)
                                price = server.recv(1024)
                                client.send(price)
                                data = AESCipher(nounceHash).decrypt(client.recv(1024))
                                dbTransact = data.split("~")[0]
                                if "No Purchase" not in data and verifySign(dbTransact, userPbKey, data.split("~")[1]):
                                    print "User authenticated Seller"
                                    price = dbTransact.split(";")[1]
                                    if price:
                                        confFile = open(os.path.join(os.path.abspath('.\\paymentDB'),"payment.csv"), "a")
                                        data = str(dbTransact)
                                        confFile.write(dbTransact.replace(";",","))
                                        confFile.write("\n")
                                        confFile.close()                                            
                                        sendData("Paid "+str(price), server, sellerPbKey)
                                        size = server.recv(1024)
                                        client.send(size)
                                        data = client.recv(1024)
                                        server.send(data)
                                        img = server.recv(40960000)
                                        client.send(img)
                                        client.close()
                                        server.close()
                                else:
                                    print "Purchase Aborted. Closing the Servers"
                                    client.close()
                                    server.close()
                            else:
                                print "Unable to get acks for public key exchange between seller and user"
                                server.close()
                                client.close()
                        else:
                            sendData("Error", server, sellerPbKey)
                            server.close()
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

class Broker:
    def __init__(self):
        try:
            server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            port = int(raw_input("Enter port to start broker server: "))
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
            client.close()