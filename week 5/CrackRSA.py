#!/bin/env python
# coding=utf-8
# CrackRSA.py
# Author: Jiangmf
# Date: 2015-05-17
#
# In an attempt to avoid the attacks on the "plain RSA" signature scheme, J.
# Random Hacker has designed her own RSA-based signature scheme. The scheme
# works as follows: the public key is a standard RSA public key (N, e), and the
# private key is the usual (N, d), where N is a 128-byte (1024-bit) integer. To
# sign a message m of length exactly 63 bytes, set
#                            M = 0x00 m 0x00 m
# (note that M is exactly 128 bytes long) and then compute the signature
# M^d mod N. (If m is shorter than 63 bytes, 0-bytes are first preprended to
# make its length exactly 63 bytes. This means that the signature on any
# message m is the same as the signatures on 0x00 m and 0x00 00 m, etc.,
# allowing easy forgery attacks. This is a known vulnerability that is not the
# point of this problem.)
#
# J. Random Hacker is so sure this scheme is secure, she is offering a bounty
# of 1 point to anyone who can forge a signature on the 63-byte message
#       Crypto is hard --- even schemes that look complex can be broken
import time
from oracle import *
from helper import *

n = 119077393994976313358209514872004186781083638474007212865571534799455802984783764695504518716476645854434703350542987348935664430222174597252144205891641172082602942313168180100366024600206994820541840725743590501646516068078269875871068596540116450747659687492528762004294694507524718065820838211568885027869
e = 65537
msg = "Crypto is hard --- even schemes that look complex can be broken"


def attack(text):
    '''Find signature for given text.'''
    Oracle_Connect()
    m = ascii_to_int(msg)
    # Factor m = m1 * m2 * 1
    # Then S(m) = S(m1) * S(m2) * 1/S(1) mod n
    m1 = m / 2
    m2 = 2
    sigma1 = Sign(m1)
    sigma2 = Sign(m2)
    sigma3_inv = modinv(Sign(1), n)

    # S(m) = S(m/2) * S(2) * 1/S(1) mod n
    sigma = (sigma1 * sigma2 * sigma3_inv) % n

    if sigma < 0:
        raise SystemExit
    if Verify(m, sigma):
        print "Oracle is working properly!"
    else:
        print "Oracle worked failed!"
    Oracle_Disconnect()
    return hex(sigma)[2:-1]

# Test Code
if __name__ == "__main__":
    t1 = time.time()
    sig = attack(msg)

    print "The sig is (HEX) '{}'".format(sig)

    t2 = time.time()
    print "time:", t2 - t1
