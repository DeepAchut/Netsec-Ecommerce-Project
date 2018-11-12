import hashlib as h

def getHash(msg):
    return h.sha1(msg).hexdigest()