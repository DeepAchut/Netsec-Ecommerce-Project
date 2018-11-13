'''
Created on 06-Nov-2018

@author: deepk
'''
g=9
p=101

def getDHkey(prKey):
    ComputedKey = (int(g)**int(prKey)) % p
    return ComputedKey

def getSessionKey(compKey, prDHkey):
    return str(((int(compKey)**int(prDHkey))%p))
