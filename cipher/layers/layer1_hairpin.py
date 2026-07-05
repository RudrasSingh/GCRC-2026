"""
Layer 1: Deterministic Hairpin Folding

Performs reversible swaps across the strand using
a fixed stride derived from stem_length.
"""
from utils.logger import get_logger

logger = get_logger("Layer1-Hairpin")


def hairpin_fold(dna: str, stem_len: int) -> str:

    logger.debug(f"hairpin_fold start: len={len(dna)} stem_len={stem_len} sample_in={dna[:64]}")

    dna_list = list(dna)

    n = len(dna_list)

    step = stem_len * 2

    for i in range(0, n - step, step):

        j = i + stem_len

        seg1 = dna_list[i:i + stem_len]
        seg2 = dna_list[j:j + stem_len]

        dna_list[i:i + stem_len] = seg2
        dna_list[j:j + stem_len] = seg1

    out = "".join(dna_list)
    logger.debug(f"hairpin_fold end: sample_out={out[:64]}")
    return out