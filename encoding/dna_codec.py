"""
DNA Encoding / Decoding Module

Responsible for:
- Converting plaintext to DNA sequence
- Converting DNA sequence back to plaintext
- Block padding and splitting
"""

# 2-bit DNA encoding
BASE_MAP = {
    "00": "A",
    "01": "T",
    "10": "C",
    "11": "G"
}

REV_BASE_MAP = {v: k for k, v in BASE_MAP.items()}


# -----------------------------
# TEXT → DNA
# -----------------------------

def text_to_dna(text: str) -> str:
    """
    Convert UTF-8 text into DNA sequence.
    Each byte (8 bits) becomes 4 DNA bases.
    """

    data = text.encode("utf-8")

    dna = ""

    for byte in data:

        bits = format(byte, "08b")

        for i in range(0, 8, 2):
            dna += BASE_MAP[bits[i:i+2]]

    return dna


# -----------------------------
# DNA → TEXT
# -----------------------------

def dna_to_text(dna: str) -> str:
    """
    Convert DNA sequence back into text.
    """

    bits = ""

    for base in dna:

        if base not in REV_BASE_MAP:
            raise ValueError(f"Invalid DNA base: {base}")

        bits += REV_BASE_MAP[base]

    bytes_out = []

    for i in range(0, len(bits), 8):

        byte = bits[i:i+8]

        if len(byte) < 8:
            break

        bytes_out.append(int(byte, 2))

    return bytes(bytes_out).decode("utf-8", errors="ignore")


# -----------------------------
# PADDING
# -----------------------------

def pad_dna(dna: str, block_size: int = 128):

    # ensure codon alignment
    while len(dna) % 3 != 0:
        dna += "A"

    remainder = len(dna) % block_size

    if remainder == 0:
        return dna, 0

    pad_len = block_size - remainder

    dna += "A" * pad_len

    return dna, pad_len

# -----------------------------
# REMOVE PADDING
# -----------------------------

def remove_padding(dna: str, pad_len: int):
    """
    Remove padding added during encryption
    """

    if pad_len == 0:
        return dna

    return dna[:-pad_len]


# -----------------------------
# BLOCK SPLITTING
# -----------------------------

def split_blocks(dna: str, block_size: int = 128):
    """
    Split DNA string into fixed size blocks
    """

    return [
        dna[i:i+block_size]
        for i in range(0, len(dna), block_size)
    ]


# -----------------------------
# JOIN BLOCKS
# -----------------------------

def join_blocks(blocks):
    """
    Combine DNA blocks into one sequence
    """

    return "".join(blocks)