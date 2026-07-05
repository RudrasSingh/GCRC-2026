"""
Key Schedule Module

Derives deterministic biological parameters
from a master key using SHA-512.
"""

import hashlib


class KeySchedule:

    def __init__(self, master_key: str):

        if not master_key:
            raise ValueError("Key cannot be empty")

        self.master_key = master_key

        digest = hashlib.sha512(master_key.encode()).digest()

        # --------------------------------
        # LFSR SEED (80 bits)
        # --------------------------------

        self.lfsr_seed = int.from_bytes(digest[:10], "big")

        if self.lfsr_seed == 0:
            self.lfsr_seed = 1

        # --------------------------------
        # NUMBER OF ROUNDS
        # --------------------------------

        self.rounds = 10 + digest[10] % 6
        # 10 – 15 rounds

        # --------------------------------
        # HAIRPIN PARAMETERS
        # --------------------------------

        self.stem_length = 4 + digest[11] % 6
        # 4 – 9 bases

        self.loop_size = 3 + digest[12] % 6
        # 3 – 8 bases

        # --------------------------------
        # HOLLIDAY WINDOW SIZE
        # --------------------------------

        self.holliday_window = 16 + digest[13] % 32
        # 16 – 47 bases

        # --------------------------------
        # TRANSPOSON LENGTH
        # --------------------------------

        self.transposon_length = 8 + digest[14] % 16
        # 8 – 23 bases

        # --------------------------------
        # SUPERCOIL TOPOLOGY FACTOR
        # --------------------------------

        self.topology_factor = 1 + digest[15] % 5
        # 1 – 5

    # --------------------------------

    def summary(self):
        """
        Print parameters (useful for debugging)
        """

        print("Key Schedule Parameters")
        print("-----------------------")
        print("Rounds:", self.rounds)
        print("LFSR Seed:", self.lfsr_seed)
        print("Stem Length:", self.stem_length)
        print("Loop Size:", self.loop_size)
        print("Holliday Window:", self.holliday_window)
        print("Transposon Length:", self.transposon_length)
        print("Topology Factor:", self.topology_factor)