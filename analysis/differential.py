import random
from collections import Counter

from utils.dna_utils import dna_to_bits


def differential_test(cipher, dna1, dna2, trials=1000):

    counter=Counter()

    for _ in range(trials):

        ct1=cipher.encrypt(dna1)
        ct2=cipher.encrypt(dna2)

        b1=dna_to_bits(ct1)
        b2=dna_to_bits(ct2)

        diff=tuple(x^y for x,y in zip(b1,b2))

        counter[diff]+=1

    return counter.most_common(5)