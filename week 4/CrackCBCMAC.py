#!/bin/env python
# coding=utf-8
# CrackCBCMAC.py
# Author: Jiangmf
# Date: 2015-05-03
#
# Implement an attack against basic CBC-MAC showing that basic CBC-MAC is not
# secure when used to authenticate/verify messages of different lengths. Here,
# you will be given the ability to obtain tags (with respect to some unknown
# key) for any 2-block (32-byte) messages of your choice; your goal is to forge
# a valid tag (with respect to the same key) on the 4-block (64-byte) message
# I, the server, hereby agree that I will pay $100 to this student. (Omit the
# final period. You should verify that the message contains exactly 64 ASCII
# characters.) You will also be given access to a verification routine that
# you can use to verify your solution.

import time
from oracle import *

sampletext = 'This sample message is 32 chars\n'
targettext = 'I, the server, hereby agree that I will pay $100 to this student'

def strxor(a, b):
        """xor two strings of different lengths"""
        strlist = [chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)]
        return "".join(strlist)

def attack(data):
    '''Find tag for given text.'''
    Oracle_Connect()
    if(len(data)%32 == 0):
        tag = Mac(data[0:32], 32)
        for i in range(1, len(data)/32):
            first16 = data[i*32:i*32+16]
            second16 = data[i*32+16:i*32+32]

            d = strxor(str(tag), first16) + second16
            tag = Mac(d, len(d))
    ret = Vrfy(data, len(data), tag)

    if (ret==1):
        print "Message verified successfully!"
    else:
        print "Message verification failed."

    Oracle_Disconnect()
    return str(tag)

# Test Code
if __name__ == "__main__":
    t1 = time.time()
    tag = attack(targettext)

    print "The tag is '{}'".format(tag)
    print "    (HEX) {}".format(tag.encode('hex'))

    t2 = time.time()
    print "time:", t2 - t1
