'''
Created on 28-Nov-2018

@author: deepk
'''
from Crypto import Random
from Crypto.PublicKey import RSA


#Generate a public/ private key pair using 4096 bits key length (512 bytes)
random_generator = Random.new().read
new_key = RSA.generate(1024, random_generator)

#The private key in PEM format
private_key = new_key.exportKey("PEM")

#The public key in PEM Format
public_key = new_key.publickey().exportKey("PEM")

print private_key
fd = open("Broker/private_key.pem", "wb")
fd.write(private_key)
fd.close()

print public_key
fd = open("Broker/public_key.pem", "wb")
fd.write(public_key)
fd.close()