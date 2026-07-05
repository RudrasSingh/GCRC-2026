"""
Layer 3: Holliday Junction Recombination

Simulates DNA strand exchange using reversible
mod-4 arithmetic between state strand and key strand.
"""

from typing import Dict
from utils.logger import get_logger

logger = get_logger("Layer3-Holliday")


# --------------------------------
# BASE ↔ NUMBER MAPPING
# --------------------------------

DNA_TO_NUM: Dict[str, int] = {
    "A": 0,
    "T": 1,
    "C": 2,
    "G": 3
}

NUM_TO_DNA: Dict[int, str] = {v: k for k, v in DNA_TO_NUM.items()}


# --------------------------------
# MIXING FUNCTION
# --------------------------------

def mix_base(a: str, b: str) -> str:
    """
    Base addition mod-4
    """

    v = (DNA_TO_NUM[a] + DNA_TO_NUM[b]) % 4

    return NUM_TO_DNA[v]


# --------------------------------
# UNMIXING FUNCTION
# --------------------------------

def unmix_base(a: str, b: str) -> str:
    """
    Reverse mod-4 operation
    """

    v = (DNA_TO_NUM[a] - DNA_TO_NUM[b]) % 4

    return NUM_TO_DNA[v]


# --------------------------------
# HOLLIDAY MIX
# --------------------------------

def holliday_mix(state: str, key: str) -> str:
    """
    Apply strand mixing across the entire sequence.
    """

    logger.debug(f"holliday_mix start: len_state={len(state)} len_key={len(key)} sample_state={state[:64]} sample_key={key[:64]}")
    if len(key) < len(state):
        raise ValueError("Key strand shorter than state strand")

    mixed = []

    for a, b in zip(state, key):

        mixed.append(mix_base(a, b))

    out = "".join(mixed)
    logger.debug(f"holliday_mix end: sample_out={out[:64]}")
    return out


# --------------------------------
# HOLLIDAY UNMIX
# --------------------------------

def holliday_unmix(state: str, key: str) -> str:
    """
    Reverse strand mixing.
    """

    logger.debug(f"holliday_unmix start: len_state={len(state)} len_key={len(key)} sample_state={state[:64]} sample_key={key[:64]}")
    if len(key) < len(state):
        raise ValueError("Key strand shorter than state strand")

    unmixed = []

    for a, b in zip(state, key):

        unmixed.append(unmix_base(a, b))

    out = "".join(unmixed)
    logger.debug(f"holliday_unmix end: sample_out={out[:64]}")
    return out