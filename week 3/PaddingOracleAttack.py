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

B = 16  # block_size


def hex_to_IntList(data):
    return [(int(data[i:i + 2], 16)) for i in range(0, len(data), 2)]


def attack(c):
    # message m ,length is shorter then ciphertext c by one block
    # initialize m = '------------------------------'
    m = [45] * (len(c) - B)
    Oracle_Connect()

    # guess from the first block to the last block
    for blk in range(0, len(c) / B - 1):
        # reset msg, only 2 blocks long
        # for the 1st run, msg = iv + c1;
        # for the 2nd run, msg = c1 + c2;
        msg = list(c[blk * B:(blk + 2) * B])

        # guess from the last byte to the first byte
        # (here, B-1 >= p >= 0)
        for p in range(B - 1, -1, -1):
            # backup a base value for the current byte before apply guess to it
            msg_p_backup = msg[p]

            # make the previous guesses applied to all the previous bytes
            # since msg'[i] = msg_p_backup xor m[i] xor PADDING
            # and msg[i] = msg_p_backup xor m[i] xor LAST_PADDING
            # so msg'[i] = msg[i] xor LAST_PADDING xor PADDING
            for i in range(B - 1, p, -1):
                msg[i] = msg[i] ^ (B - p - 1) ^ (B - p)

            # guess a value 'G' for the current byte
            for G in range(2, 127):
                # send (msg_p_backup xor G xor PADDING) for verify
                msg[p] = msg_p_backup ^ G ^ (B - p)
#                print "Send: ", G, msg
                rc = Oracle_Send(msg, 2)

                if rc:
                    # guess correct ,set m[pos] is our guess value 'G'
                    m[blk * B + p] = G
                    print "The plaintext is :'{}'".format(''.join(map(chr, m)))
                    break

                # all guess wrong, means my program is wrong
                if G >= 126:
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
