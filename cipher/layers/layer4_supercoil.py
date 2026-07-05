"""
Layer 4: DNA Supercoiling

Uses LFSR-driven rotation to simulate DNA topology changes.
The rotation is reversible.
"""

from utils.lfsr import LFSR
from utils.logger import get_logger

logger = get_logger("Layer4-Supercoil")


def rotate_left(s: str, k: int) -> str:

    if len(s) == 0:
        return s

    k %= len(s)

    return s[k:] + s[:k]


def rotate_right(s: str, k: int) -> str:

    if len(s) == 0:
        return s

    k %= len(s)

    return s[-k:] + s[:-k]


# ------------------------------------------------
# FORWARD
# ------------------------------------------------

def supercoil_transform(dna: str, topology_factor: int, lfsr: LFSR) -> str:

    logger.debug(f"supercoil_transform start: len={len(dna)} topology_factor={topology_factor} sample_in={dna[:64]}")
    if len(dna) == 0:
        return dna

    rotation = lfsr.randint(len(dna)) * topology_factor

    rotation %= len(dna)

    out = rotate_left(dna, rotation)
    logger.debug(f"supercoil_transform end: rotation={rotation} sample_out={out[:64]}")
    return out


# ------------------------------------------------
# INVERSE
# ------------------------------------------------

def supercoil_inverse(dna: str, topology_factor: int, lfsr: LFSR) -> str:

    logger.debug(f"supercoil_inverse start: len={len(dna)} topology_factor={topology_factor} sample_in={dna[:64]}")
    if len(dna) == 0:
        return dna

    rotation = lfsr.randint(len(dna)) * topology_factor

    rotation %= len(dna)

    out = rotate_right(dna, rotation)
    logger.debug(f"supercoil_inverse end: rotation={rotation} sample_out={out[:64]}")
    return out