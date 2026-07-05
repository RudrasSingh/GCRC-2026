BASE_TO_INT = {
    "A": 0,
    "T": 1,
    "C": 2,
    "G": 3
}

INT_TO_BASE = ["A", "T", "C", "G"]

from utils.logger import get_logger

logger = get_logger("Layer6-Polymerase")


# ------------------------------------------------
# Polymerase propagation (forward)
# ------------------------------------------------

def polymerase_forward(dna: str):

    logger.debug(f"polymerase_forward start: len={len(dna)} sample_in={dna[:64]}")

    if len(dna) == 0:
        return dna

    out = []

    prev = BASE_TO_INT[dna[0]]

    out.append(dna[0])

    for b in dna[1:]:

        cur = BASE_TO_INT[b]

        val = (cur ^ prev) % 4

        out.append(INT_TO_BASE[val])

        prev = val

    out_s = "".join(out)
    logger.debug(f"polymerase_forward end: sample_out={out_s[:64]}")
    return out_s


# ------------------------------------------------
# Polymerase reverse
# ------------------------------------------------

def polymerase_inverse(dna: str):

    logger.debug(f"polymerase_inverse start: len={len(dna)} sample_in={dna[:64]}")

    if len(dna) == 0:
        return dna

    out = []

    prev = BASE_TO_INT[dna[0]]

    out.append(dna[0])

    for b in dna[1:]:

        cur = BASE_TO_INT[b]

        val = (cur ^ prev) % 4

        out.append(INT_TO_BASE[val])

        prev = cur

    out_s = "".join(out)
    logger.debug(f"polymerase_inverse end: sample_out={out_s[:64]}")
    return out_s