import random
import numpy as np

from utils.dna_utils import dna_to_bits, bits_to_dna


def avalanche_test(cipher, dna):

    ct1=cipher.encrypt(dna)

    bits=dna_to_bits(dna)

    flip=random.randint(0,len(bits)-1)

    bits[flip]^=1

    dna2=bits_to_dna(bits)

    ct2=cipher.encrypt(dna2)

    b1=dna_to_bits(ct1)
    b2=dna_to_bits(ct2)

    diff=sum(x^y for x,y in zip(b1,b2))

    return diff/len(b1)