#!/bin/env python
# coding=utf-8
# PaddingOracleAttack.py
# Author: Jiangmf
# Date: 2015-07-26
#
# Decrypt a challenge ciphertext generated using AES in CBC-mode with PKCS #5
# padding. (Note: technically this is PKCS #7 padding, since the block size of
# AES is 16 bytes. But the padding is done in exactly the same way as PKCS #5
# padding.) To do so, you will be given access to a server that will decrypt
# any ciphertexts you send it (using the same key that was used to generate the
# challenge ciphertext)...but that will only tell you whether or not decryption
# results in an error!
import time
from oracle import *

ciphertexts = ('9F0B13944841A832B2421B9EAF6D9836813EC9D944A5C834'
               '7A7CA69AA34D8DC0DF70E343C4000A2AE35874CE75E64C31')

B = 16 # block_size

def hex_to_IntList(data):
    return [(int(data[i:i+2],16)) for i in range(0, len(data), 2)]

def get_block(c, blk):
    return c[blk*B:(blk+1)*B]

def attack(c):
    # message m ,length is shorter then ciphertext c by one block
    # initialize m = '------------------------------'
    #m = [45] * (len(c) - B)
    m = map(ord,'Yay! You get an ') + [45]*16
    Oracle_Connect()

    # guess from the first block to the last block
    for blk in range(2, len(c) / B):
        #for the 1st block, iv = iv;
        #for the 2nd block, iv = c1;
        iv = get_block(c, blk-1)

        #reset msg, '+' is list concat
        msg = list(iv) + get_block(c, blk)

        # guess from the last byte to the first byte (here, 0<=p<=B-1)
        for p in range(B-1, -1, -1):
            #make the previous guesses applied to all the previous bytes
            #so that iv[i] = iv[i] xor m[pos] xor (B-p)
            #(here, p+1<=i<=B-1 ,iv[B-1] is the last byte)
            for i in range(B-1, p, -1):
                msg[i] = iv[i] ^ m[(blk-1)*B+ i] ^ (B-p)

            # guess a value 'G' for the current byte
            for G in range(0, 128):
                #send (iv[p] xor G xor PADDING) for the new guess byte
                msg[p] = iv[p] ^ G ^ (B-p)
                print "Send ", G
                rc = Oracle_Send(msg, 2)

                if rc:
                    #guess correct ,set m[pos] is our guess value 'G'
                    m[(blk-1)*B+ p] = G
                    print "Current message is :'{}'".format(''.join(map(chr, m)))
                    break

                # all guess wrong, means my program is wrong
                if G >= 128:
                    print "Something wrong!"
                    return
    Oracle_Disconnect()
    return map(chr, m)


# Test Code
if __name__ == "__main__":
    t1 = time.time()
    p = attack(hex_to_IntList(ciphertexts))

    print "The plaintext is '{}'".format(''.join(p))
    print "    (HEX) {}".format(''.join(p).encode('hex'))

    t2 = time.time()
    print "time:", t2 - t1
