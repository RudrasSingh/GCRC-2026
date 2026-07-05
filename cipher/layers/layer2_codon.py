"""
Layer 2: Codon Ecology Substitution

Implements synonymous codon substitution driven by LFSR.
This creates nonlinear substitution similar to an S-box.
"""

from typing import Dict, List
from utils.lfsr import LFSR
from utils.logger import get_logger

logger = get_logger("Layer2-Codon")


# ---------------------------------------------------
# STANDARD GENETIC CODE (DNA codons → amino acids)
# ---------------------------------------------------

GENETIC_CODE: Dict[str, str] = {

    "TTT":"F","TTC":"F",
    "TTA":"L","TTG":"L",
    "CTT":"L","CTC":"L","CTA":"L","CTG":"L",

    "ATT":"I","ATC":"I","ATA":"I",
    "ATG":"M",

    "GTT":"V","GTC":"V","GTA":"V","GTG":"V",

    "TCT":"S","TCC":"S","TCA":"S","TCG":"S",
    "AGT":"S","AGC":"S",

    "CCT":"P","CCC":"P","CCA":"P","CCG":"P",

    "ACT":"T","ACC":"T","ACA":"T","ACG":"T",

    "GCT":"A","GCC":"A","GCA":"A","GCG":"A",

    "TAT":"Y","TAC":"Y",
    "TAA":"*","TAG":"*",

    "CAT":"H","CAC":"H",
    "CAA":"Q","CAG":"Q",

    "AAT":"N","AAC":"N",
    "AAA":"K","AAG":"K",

    "GAT":"D","GAC":"D",
    "GAA":"E","GAG":"E",

    "TGT":"C","TGC":"C",
    "TGA":"*",
    "TGG":"W",

    "CGT":"R","CGC":"R","CGA":"R","CGG":"R",
    "AGA":"R","AGG":"R",

    "GGT":"G","GGC":"G","GGA":"G","GGG":"G"
}


# ---------------------------------------------------
# BUILD SYNONYMOUS CODON GROUPS
# ---------------------------------------------------

AA_TO_CODONS: Dict[str, List[str]] = {}

for codon, aa in GENETIC_CODE.items():

    if aa not in AA_TO_CODONS:
        AA_TO_CODONS[aa] = []

    AA_TO_CODONS[aa].append(codon)

# sort codons for deterministic order
for aa in AA_TO_CODONS:
    AA_TO_CODONS[aa].sort()


# ---------------------------------------------------
# CODON SUBSTITUTION
# ---------------------------------------------------

def codon_substitute(dna: str, lfsr: LFSR) -> str:
    """
    Encrypt codons using synonymous substitution.
    """
    logger.debug(f"codon_substitute start: len={len(dna)} sample_in={dna[:64]}")

    dna_list = list(dna)

    n = len(dna_list)

    for i in range(0, n - 2, 3):

        codon = "".join(dna_list[i:i+3])

        aa = GENETIC_CODE.get(codon)

        shift = lfsr.byte()

        if aa is None:
            continue

        synonyms = AA_TO_CODONS[aa]

        if len(synonyms) == 1:
            continue

        idx = synonyms.index(codon)

        new_idx = (idx + shift) % len(synonyms)

        new_codon = synonyms[new_idx]

        dna_list[i:i+3] = list(new_codon)
    out = "".join(dna_list)
    logger.debug(f"codon_substitute end: sample_out={out[:64]}")

    return "".join(dna_list)


# ---------------------------------------------------
# INVERSE SUBSTITUTION
# ---------------------------------------------------

def codon_unsubstitute(dna: str, lfsr: LFSR) -> str:
    """
    Reverse codon substitution.
    """
    logger.debug(f"codon_unsubstitute start: len={len(dna)} sample_in={dna[:64]}")

    dna_list = list(dna)

    n = len(dna_list)

    for i in range(0, n - 2, 3):

        codon = "".join(dna_list[i:i+3])

        aa = GENETIC_CODE.get(codon)

        shift = lfsr.byte()

        if aa is None:
            continue

        synonyms = AA_TO_CODONS[aa]

        if len(synonyms) == 1:
            continue

        idx = synonyms.index(codon)

        new_idx = (idx - shift) % len(synonyms)

        new_codon = synonyms[new_idx]

        dna_list[i:i+3] = list(new_codon)
    out = "".join(dna_list)
    logger.debug(f"codon_unsubstitute end: sample_out={out[:64]}")

    return "".join(dna_list)