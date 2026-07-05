import os
import numpy as np

from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import text_to_dna

from utils.dna_utils import dna_to_bits
from analysis.avalanche import avalanche_test
from analysis.randomness import entropy, chi_square, serial_corr


def random_message():

    return os.urandom(32).hex()


def run_metrics(trials=1000):

    cipher=GCRC("test-key")

    avalanche_vals=[]
    all_bits=[]

    for _ in range(trials):

        msg=random_message()

        dna=text_to_dna(msg)

        ct=cipher.encrypt(dna)

        bits=dna_to_bits(ct)

        all_bits.extend(bits)

        avalanche_vals.append(avalanche_test(cipher,dna))

    return {

        "avalanche": float(np.mean(avalanche_vals)),
        "entropy": float(entropy(all_bits)),
        "chi_square": float(chi_square(all_bits)),
        "serial_corr": float(serial_corr(all_bits))

    }