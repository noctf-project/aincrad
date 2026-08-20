#!/usr/bin/env python3

# adapted from https://github.com/balsn/proof-of-work/blob/master/solver/python3.py
import hashlib
import sys
import base64
import hmac

if sys.argv[1] == 's':
    difficulty = int(sys.argv[2])
    prefix = base64.urlsafe_b64decode(sys.argv[3] + '==')
    zeros = '0' * difficulty

    def is_valid(digest):
        if sys.version_info.major == 2:
            digest = [ord(i) for i in digest]
        bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
        return bits[:difficulty] == zeros


    i = 0
    while True:
        i += 1
        d = str(i).encode('ascii', 'ignore')
        s = prefix + d
        if is_valid(hashlib.sha256(s).digest()):
            print(base64.urlsafe_b64encode(d))
            exit(0)
elif sys.argv[1] == 'b':
    bypass = base64.urlsafe_b64decode(sys.argv[2])
    mac = hmac.new(bypass, sys.argv[3].encode(), hashlib.sha256).digest()
    print(base64.urlsafe_b64encode(mac))