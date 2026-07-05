"""
Layer 5: Transposon Hopping

Implements reversible transposon movement using
segment rotation between two positions.
"""

from utils.lfsr import LFSR
from utils.logger import get_logger

logger = get_logger("Layer5-Transposon")


def rotate_left(s: str, k: int) -> str:

    k %= len(s)

    return s[k:] + s[:k]


def rotate_right(s: str, k: int) -> str:

    k %= len(s)

    return s[-k:] + s[:-k]


# --------------------------------
# FORWARD TRANSFORMATION
# --------------------------------

def transposon_forward(dna: str, lfsr: LFSR, tlen: int) -> str:

    logger.debug(f"transposon_forward start: len={len(dna)} tlen={tlen} sample_in={dna[:64]}")
    n = len(dna)

    if n <= tlen + 4:
        logger.debug("transposon_forward skipped: strand too short")
        return dna

    src = lfsr.randint(n - tlen)

    hop = lfsr.randint(n - tlen)

    tgt = (src + hop) % (n - tlen)

    if tgt <= src:
        logger.debug("transposon_forward no-op: tgt <= src")
        return dna

    segment = dna[src:tgt + tlen]

    rotated = rotate_left(segment, tlen)

    out = dna[:src] + rotated + dna[tgt + tlen:]
    logger.debug(f"transposon_forward end: src={src} tgt={tgt} sample_out={out[:64]}")
    return out


# --------------------------------
# INVERSE TRANSFORMATION
# --------------------------------

def transposon_inverse(dna: str, lfsr: LFSR, tlen: int) -> str:

    logger.debug(f"transposon_inverse start: len={len(dna)} tlen={tlen} sample_in={dna[:64]}")
    n = len(dna)

    if n <= tlen + 4:
        logger.debug("transposon_inverse skipped: strand too short")
        return dna

    src = lfsr.randint(n - tlen)

    hop = lfsr.randint(n - tlen)

    tgt = (src + hop) % (n - tlen)

    if tgt <= src:
        logger.debug("transposon_inverse no-op: tgt <= src")
        return dna

    segment = dna[src:tgt + tlen]

    rotated = rotate_right(segment, tlen)

    out = dna[:src] + rotated + dna[tgt + tlen:]
    logger.debug(f"transposon_inverse end: src={src} tgt={tgt} sample_out={out[:64]}")
    return out