"""
GCRC Cipher Controller
Coordinates all biological cipher layers.
"""

from typing import List

from config.key_schedule import KeySchedule
from utils.lfsr import LFSR
from utils.logger import get_logger

from cipher.layers.layer1_hairpin import hairpin_fold
from cipher.layers.layer2_codon import codon_substitute, codon_unsubstitute
from cipher.layers.layer3_holliday import holliday_mix, holliday_unmix
from cipher.layers.layer4_supercoil import supercoil_transform, supercoil_inverse
from cipher.layers.layer5_transposon import transposon_forward, transposon_inverse
from cipher.layers.layer6_polymerase import polymerase_forward, polymerase_inverse


class GCRC:

    def __init__(self, key: str):

        self.key = key
        self.ks = KeySchedule(key)

        self.logger = get_logger("GCRC")
        self.logger.debug(
            f"KeySchedule created: rounds={self.ks.rounds} "
            f"seed={self.ks.lfsr_seed} "
            f"stem_length={self.ks.stem_length} "
            f"transposon_length={self.ks.transposon_length} "
            f"topology_factor={self.ks.topology_factor}"
        )

        self.seed = self.ks.lfsr_seed
        self.rounds = self.ks.rounds

    # ------------------------------------------------
    # KEY STREAM GENERATION
    # ------------------------------------------------

    def _key_stream(self, length: int, lfsr) -> str:

        bases = ["A", "T", "C", "G"]
        out = []

        for _ in range(length):
            out.append(bases[lfsr.byte() % 4])

        try:
            self.logger.debug(
                f"_key_stream generated (len={length}) sample={''.join(out)[:64]}"
            )
        except Exception:
            pass

        return "".join(out)

    # ------------------------------------------------
    # ENCRYPT
    # ------------------------------------------------

    def encrypt(self, dna: str) -> str:

        state = dna

        # independent RNG streams
        lfsr_codon = LFSR(self.seed + 1)
        lfsr_supercoil = LFSR(self.seed + 2)
        lfsr_transposon = LFSR(self.seed + 3)
        lfsr_key = LFSR(self.seed + 4)

        for r in range(self.rounds):

            self.logger.debug(
                f"Round {r+1} start: input_len={len(state)} sample={state[:64]}"
            )

            # Layer 1: Hairpin
            state = hairpin_fold(state, self.ks.stem_length)
            self.logger.debug(f"Round {r+1} after Hairpin: sample={state[:64]}")

            # Layer 2: Codon substitution
            state = codon_substitute(state, lfsr_codon)
            self.logger.debug(f"Round {r+1} after Codon: sample={state[:64]}")

            # Layer 3: Holliday recombination
            key_strand = self._key_stream(len(state), lfsr_key)
            self.logger.debug(f"Round {r+1} key_strand sample={key_strand[:64]}")

            state = holliday_mix(state, key_strand)
            self.logger.debug(f"Round {r+1} after Holliday: sample={state[:64]}")

            # Layer 4: Supercoiling
            state = supercoil_transform(
                state,
                self.ks.topology_factor,
                lfsr_supercoil
            )
            self.logger.debug(f"Round {r+1} after Supercoil: sample={state[:64]}")

            # Layer 5: Transposon hopping
            state = transposon_forward(
                state,
                lfsr_transposon,
                self.ks.transposon_length
            )
            self.logger.debug(f"Round {r+1} after Transposon: sample={state[:64]}")

            # Layer 6: Polymerase propagation
            state = polymerase_forward(state)
            self.logger.debug(f"Round {r+1} after Polymerase: sample={state[:64]}")

        return state

    # ------------------------------------------------
    # ENCRYPT WITH ROUND TRACE
    # ------------------------------------------------

    def encrypt_with_trace(self, dna: str) -> List[str]:
        """
        Same as encrypt(), but returns the state after each round.
        Used for round-by-round avalanche analysis.
        """

        state = dna
        states = []

        # recreate same RNG streams
        lfsr_codon = LFSR(self.seed + 1)
        lfsr_supercoil = LFSR(self.seed + 2)
        lfsr_transposon = LFSR(self.seed + 3)
        lfsr_key = LFSR(self.seed + 4)

        for r in range(self.rounds):

            # Layer 1
            state = hairpin_fold(state, self.ks.stem_length)

            # Layer 2
            state = codon_substitute(state, lfsr_codon)

            # Layer 3
            key_strand = self._key_stream(len(state), lfsr_key)
            state = holliday_mix(state, key_strand)

            # Layer 4
            state = supercoil_transform(
                state,
                self.ks.topology_factor,
                lfsr_supercoil
            )

            # Layer 5
            state = transposon_forward(
                state,
                lfsr_transposon,
                self.ks.transposon_length
            )

            # Layer 6
            state = polymerase_forward(state)

            states.append(state)

            self.logger.debug(
                f"encrypt_with_trace round {r+1}: sample={state[:64]}"
            )

        return states

    # ------------------------------------------------
    # DECRYPT
    # ------------------------------------------------

    def decrypt(self, dna: str) -> str:

        state = dna

        lfsr_codon = LFSR(self.seed + 1)
        lfsr_supercoil = LFSR(self.seed + 2)
        lfsr_transposon = LFSR(self.seed + 3)
        lfsr_key = LFSR(self.seed + 4)

        codon_states = []
        supercoil_states = []
        transposon_states = []
        key_states = []

        # simulate forward RNG usage
        for r in range(self.rounds):

            codon_states.append(lfsr_codon.get_state())
            supercoil_states.append(lfsr_supercoil.get_state())
            transposon_states.append(lfsr_transposon.get_state())
            key_states.append(lfsr_key.get_state())

            codons = len(state) // 3
            for _ in range(codons):
                lfsr_codon.byte()

            lfsr_supercoil.randint(len(state))

            lfsr_transposon.randint(len(state))
            lfsr_transposon.randint(len(state))

            for _ in range(len(state)):
                lfsr_key.byte()

        self.logger.debug(f"Starting decrypt: input_len={len(dna)}")

        for r in reversed(range(self.rounds)):

            lfsr_codon.set_state(codon_states[r])
            lfsr_supercoil.set_state(supercoil_states[r])
            lfsr_transposon.set_state(transposon_states[r])
            lfsr_key.set_state(key_states[r])

            # Layer 6 inverse
            state = polymerase_inverse(state)

            # Layer 5 inverse
            state = transposon_inverse(
                state,
                lfsr_transposon,
                self.ks.transposon_length
            )

            # Layer 4 inverse
            state = supercoil_inverse(
                state,
                self.ks.topology_factor,
                lfsr_supercoil
            )

            # Layer 3 inverse
            key_strand = self._key_stream(len(state), lfsr_key)
            state = holliday_unmix(state, key_strand)

            # Layer 2 inverse
            state = codon_unsubstitute(state, lfsr_codon)

            # Layer 1 inverse
            state = hairpin_fold(state, self.ks.stem_length)

        return state