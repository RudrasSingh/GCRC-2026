import os
import math
import random
import numpy as np
from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import text_to_dna
from utils.dna_utils import dna_to_bits, bits_to_dna

def random_message():
    return os.urandom(32).hex()

def avalanche_test(cipher, dna):
    ct1 = cipher.encrypt(dna)
    bits = dna_to_bits(dna)
    flip = random.randint(0, len(bits) - 1)
    bits[flip] ^= 1
    dna2 = bits_to_dna(bits)
    ct2 = cipher.encrypt(dna2)
    b1 = dna_to_bits(ct1)
    b2 = dna_to_bits(ct2)
    diff = sum(x ^ y for x, y in zip(b1, b2))
    return diff / len(b1)

def entropy(bits):
    p = sum(bits) / len(bits)
    if p == 0 or p == 1:
        return 0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))

def chi_square(bits):
    ones = sum(bits)
    zeros = len(bits) - ones
    expected = len(bits) / 2
    return ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected

def serial_corr(bits):
    n = len(bits)
    mean = sum(bits) / n
    num = sum((bits[i] - mean) * (bits[i + 1] - mean) for i in range(n - 1))
    den = sum((b - mean) ** 2 for b in bits)
    if den == 0:
        return 0
    return num / den

def run_metrics(trials=1000):
    cipher = GCRC("test-key")
    avalanche_vals = []
    all_bits = []
    for _ in range(trials):
        msg = random_message()
        dna = text_to_dna(msg)
        ct = cipher.encrypt(dna)
        bits = dna_to_bits(ct)
        all_bits.extend(bits)
        avalanche_vals.append(avalanche_test(cipher, dna))
    return {
        "avalanche": float(np.mean(avalanche_vals)),
        "entropy": float(entropy(all_bits)),
        "chi_square": float(chi_square(all_bits)),
        "serial_corr": float(serial_corr(all_bits))
    }
