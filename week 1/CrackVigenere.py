#!/bin/env python
# coding=utf-8
# CrackVigenere.py
# Author: Jiangmf
# Date: 2015-03-30
#
# Write a program that allows you to "crack" ciphertexts generated using a
# Vigenere-like cipher, where byte-wise XOR is used instead of addition modulo
# 26.
#
# KEY_LENGTH can be anything from 1 to 13
import time

ciphertext = (
    'F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF'
    '7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77'
    'F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3'
    'D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D3'
    '20ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3C'
    'B84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF'
    '47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85F'
    'CE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF'
    '67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27A'
    'FCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0'
    'D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD'
    '24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327'
    'A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA1'
    '4794').decode('hex')

# @see https://en.wikipedia.org/wiki/Letter_frequency
letterfreq = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
    's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
    'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
    'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07}


def strxor_lp(a, b):
    """xor two strings of different lengths, loop xor"""
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return a
    else:
        strlist = [chr(ord(a[i]) ^ ord(b[i % len(b)])) for i in range(len(a))]
        return "".join(strlist)


def crack(ctext, min_key_length=0, max_key_length=0):
    """crack ciphertexts generated using a Vigenere-like cipher"""
    # Step I -- Determing the key length
    length = find_length(ctext, min_key_length, max_key_length)
    # Step II -- Determing the ith byte of the key
    bytes = find_bytes(ctext, length)
    return bytes


def find_length(ctext, min_key_length, max_key_length):
    """find key length in [min,max]"""
    if(min_key_length <= 0):
        min_key_length = min(len(ctext), 2)
    if(max_key_length <= 0):
        max_key_length = len(ctext) / 10
    #Guess a intial length, update the distribution to overwrite it
    length = min_key_length
    distribution = 1.0 / 256
    print "initial distribution:", distribution
    for N in range(min_key_length, max_key_length + 1):
        d = 0.0
        for i in range(N):
            # Guess the length be N, then look at every Nth character stream of
            # the ciphertexts, maximum distribution, then the N is our goal.
            stream = list(ctext[i::N])
            # Sum all stream's distribution in order to take average
            # distribution
            d += sum((1.0 * stream.count(p) / len(stream))
                     ** 2 for p in stream)
        # Take average distribution for every stream
        d /= N
        # Update distribution
        if(d > distribution):
            distribution = d
            length = N
            print "length, distribution updated: {},{}".format(N, d)
    return length


def find_bytes(ctext, length):
    """find key bytes in given length"""
    streams = [list(ctext[i::length]) for i in range(length)]
    key = ['\x00'] * length
    # Guess key byte by byte
    for i in range(length):
        distribution = 1.0 / 256
        # Guess the key character b using the first character s0 in the stream
        for s0 in range(32, 128):
            b = ord(streams[i][0]) ^ s0
            # Test b with the other characters in the stream
            xor_result = [ord(s) ^ b for s in streams[i][1:]]
            if all(ascii_valid(s_xor_b) for s_xor_b in xor_result):
                # Calculate the distribution under b
                d = sum(xor_result.count(ord(c)) * letterfreq[c]
                        for c in 'abcdefghijklmnopqrstuvwxyz')
                # Update distribution
                if(d > distribution):
                    key[i] = chr(b)
                    distribution = d
                    print "key {}, distribution updated: {}, {}".format(
                        i, key[i].encode('hex'), d)
    return "".join(key)


def ascii_valid(ch):
    return ch >= 32 and ch <= 127

# Test Code
if __name__ == "__main__":
    t1 = time.time()
    secret = crack(ciphertext, 2, 13)
    print "The key is:"
    print secret.encode('hex')
    print "The plaintext is:"
    print strxor_lp(ciphertext, secret)

    t2 = time.time()
    print "time:", t2 - t1
