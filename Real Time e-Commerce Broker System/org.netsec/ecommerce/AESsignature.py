'''
Created on 17-Nov-2018

@author: deepk
'''
from base64 import (
    b64encode,
    b64decode,
)

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

digest = SHA256.new()

def signData(msg, private_key):
    digest.update(msg)  
    private_key = RSA.importKey(private_key)
    # Load private key and sign message
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(digest)
    return b64encode(sig)

def verifySign(msg, publicKey, sig):
    publicKey = RSA.importKey(publicKey)
    digest.update(msg)
    # Load public key and verify message
    verifier = PKCS1_v1_5.new(publicKey)
    if verifier.verify(digest, b64decode(sig)):
        return True
    else:
        return False