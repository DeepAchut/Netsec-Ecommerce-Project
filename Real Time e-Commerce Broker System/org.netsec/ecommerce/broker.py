'''
Created on 06-Nov-2018

@author: deepk
'''
import random
import socket
import thread

from HashGenerator import getHash
from RSAencryption import generateRSAkey, decryptMsg

def exchangeRSAPbKey(server,key):
    senderkey = ""
    try:
        server.send(key)
        senderPbKey = server.recv(2048)
        if senderPbKey != "":
            print "User Pb Key"
            print senderPbKey
            server.send("ACK")
            ack = server.recv(1024)
            if ack == "ACK":
                server.send(getHash(key))
                senderPbKeyHash = server.recv(1024)
                print ("User public key hash in Broker"+senderPbKeyHash)
                if senderPbKeyHash == getHash(senderPbKey):
                    senderkey = senderPbKey
                else:
                    print "Sender Pb key doesn't match"
    except Exception as e:
        print "Unable to get broker public key"
        print e
    return senderkey

prDHKey = random.randint(7,12)

def onUserConnect(client,addr):
    try:
        key = generateRSAkey()
        pukey = key.publickey().exportKey()
        userPbKey = exchangeRSAPbKey(client, pukey)
        if userPbKey:
            data = decryptMsg(client.recv(1024), key)
            if data:
                print "Seller IP:Port"
                print data            
    except Exception as e:
        print "Unable to process user message in broker"
        print e                             
    return 0

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
                if clienttype == "User":
                    print "User Connected"
                    thread.start_new_thread(onUserConnect(client,addr))
                else:
                    print "Unidentified Client type"
        except Exception as e:
            print e
            print "Unable to start server. Check Server Address or Port"