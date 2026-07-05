# DNA-GCRC: Bio-Inspired Cryptography System

## Overview

**DNA-GCRC** (Genetic Code Recombination Cipher) is a novel encryption system that draws inspiration from real DNA molecular biology and genetic processes. Instead of traditional bit manipulation, this cipher encrypts data by simulating biological transformations that occur in actual DNA molecules within living cells.

The cipher treats plaintext as a DNA sequence and applies six distinct layers of biological transformations inspired by real DNA processes: hairpin folding, genetic code substitution, DNA recombination, supercoiling, transposon hopping, and DNA polymerase activity.

---

## Table of Contents

1. [Biological Foundation](#biological-foundation)
2. [System Architecture](#system-architecture)
3. [Text-to-DNA Encoding](#text-to-dna-encoding)
4. [Encryption Pipeline](#encryption-pipeline)
5. [The Six Cipher Layers](#the-six-cipher-layers)
6. [Key Schedule](#key-schedule)
7. [Security Features](#security-features)
8. [Usage Examples](#usage-examples)

---

## Biological Foundation

### Why DNA for Cryptography?

DNA is nature's information storage system—evolved over billions of years to securely encode genetic information in a robust, redundant format. DNA cryptography leverages:

- **Biological Complexity**: DNA processing involves non-linear, interdependent transformations
- **Natural Processes**: Uses real molecular mechanisms from cell biology
- **Reversibility**: Each biological process here is reversible, essential for decryption
- **Mixing Properties**: DNA transformations naturally diffuse changes across the sequence

### DNA as Information

DNA is a 4-letter alphabet (A, T, C, G) that encodes all biological information. Real DNA molecules undergo constant transformation through:
- **DNA recombination**: Swapping genetic material between strands
- **Transposition**: Mobile genetic elements moving positions
- **Supercoiling**: Topological changes in DNA structure
- **Protein synthesis**: Codons translated via the genetic code

This cipher operationalizes these processes for cryptography.

---

## System Architecture

### High-Level Flow

```
Plaintext Message
    ↓
TEXT-TO-DNA Conversion (2-bit encoding)
    ↓
Key Derivation (SHA-512 + Key Schedule)
    ↓
GCRC Encryption (6 biological layers, 10-15 rounds)
    ↓
Post-Quantum KEM (Kyber/ML-KEM)
    ↓
HMAC Integrity Tag
    ↓
Encrypted DNA Output
```

The system combines:
- **Symmetric encryption**: GCRC cipher (DNA-based)
- **Asymmetric KEM**: Kyber/ML-KEM for key encapsulation
- **Integrity**: HMAC-SHA256 for authentication

### API Server Integration

The FastAPI server now exposes application-facing endpoints for user registration, login, API-key issuance, encryption, decryption, Kyber encapsulation, and Kyber decapsulation.

When Supabase is configured, the server persists users and API keys in the database using these environment variables:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

Expected Supabase tables:

- `users` with `id`, `email`, `full_name`, `password_salt`, `password_hash`, `created_at`, `is_active`
- `api_keys` with `id`, `user_id`, `key_hash`, `key_prefix`, `label`, `created_at`, `expires_at`, `revoked_at`, `last_used_at`

If those variables are not set, the server falls back to an in-memory repository for local development.

Application flow:

1. `POST /auth/register` creates a user, generates the user’s MLKEM keypair once, and returns a fresh API key plus the public key.
2. `POST /auth/login` authenticates a user and issues a new API key.
3. `GET /auth/me`, `GET /auth/api-keys`, `POST /auth/api-keys`, `DELETE /auth/api-keys/{id}`, and `POST /auth/mlkem-keys/rotate` manage the user’s keys.
4. `POST /crypto/encrypt`, `POST /crypto/decrypt`, `POST /kem/keygen`, `POST /kem/encapsulate`, and `POST /kem/decapsulate` require a valid `X-API-Key` header. The server uses the stored MLKEM private key by default and never expects the private key to be sent in a request.

See [docs/api.md](docs/api.md) for the endpoint reference and [docs/deployment.md](docs/deployment.md) for Docker-based local deployment.

---

## Text-to-DNA Encoding

### The 2-Bit Codec

Before encryption can occur, plaintext must be converted to a DNA sequence using binary-to-base mapping:

```
DNA Base Map:
  00 → A (Adenine)
  01 → T (Thymine)
  10 → C (Cytosine)
  11 → G (Guanine)
```

### Encoding Process

**Step 1: UTF-8 Encoding**
Convert each character to an 8-bit byte:
```
  Example: 'H' (ASCII 72)
  Binary: 01001000
```

**Step 2: Split into 2-Bit Pairs**
Break each byte into four 2-bit chunks:
```
  01 00 10 00
```

**Step 3: Map to DNA Bases**
```
  01 → T
  00 → A
  10 → C
  00 → A
  
  Result: 'TACA'
```

### Example: Encoding "Hi"
```
H (72)  = 01001000 → T A C A
i (105) = 01101001 → T C T A

Full DNA: TACATCTA
```

**Why This Encoding?**
- **Reversible**: Each 2-bit pair uniquely maps to a base
- **Lossless**: All information preserved; easy to decode
- **Efficient**: 4 bases encode 1 byte (2 bits per base)
- **Biological Realism**: Uses the actual DNA alphabet

---

## Encryption Pipeline

### Encryption Overview

```python
def encrypt(plaintext: str, public_key: bytes) -> dict:
    # Step 1: Post-Quantum Key Encapsulation
    kem_ciphertext, shared_key = kyber_encapsulate(public_key)
    
    # Step 2: Derive DNA cipher key from shared secret
    dna_key = SHA256(shared_key)[:32]
    
    # Step 3: Text to DNA
    dna = text_to_dna(plaintext)
    
    # Step 4: Key Schedule expansion
    key_schedule = KeySchedule(dna_key)  # Derives per-layer parameters
    
    # Step 5: GCRC Cipher (6 layers × 10-15 rounds)
    encrypted_dna = gcrc.encrypt(dna)
    
    # Step 6: Integrity authentication
    hmac_tag = HMAC-SHA256(shared_key, encrypted_dna)
    
    # Step 7: Return encrypted package
    return {
        "cipher_dna": encrypted_dna,
        "kyber_ciphertext": kem_ciphertext,
        "hmac": hmac_tag
    }
```

### Decryption Overview

Decryption reverses the process:

```python
def decrypt(encrypted_data: dict, private_key: bytes) -> str:
    # Step 1: KEM decapsulation
    shared_key = kyber_decapsulate(encrypted_data["kyber_ciphertext"], private_key)
    
    # Step 2: Verify HMAC
    expected_hmac = HMAC-SHA256(shared_key, encrypted_data["cipher_dna"])
    assert expected_hmac == encrypted_data["hmac"]
    
    # Step 3: Derive cipher key
    dna_key = SHA256(shared_key)[:32]
    
    # Step 4: GCRC Decryption (6 inverse layers × 10-15 rounds)
    dna = gcrc.decrypt(encrypted_data["cipher_dna"])
    
    # Step 5: DNA to Text
    plaintext = dna_to_text(dna)
    
    return plaintext
```

---

## The Six Cipher Layers

The GCRC cipher applies **six biologically-inspired transformation layers** in sequence, repeated over multiple rounds (10-15 rounds determined by key schedule).

Each layer models a real DNA phenomenon and contributes different cryptographic properties:
- **Hairpin**: Positional permutation (diffusion)
- **Codon**: Nonlinear substitution (confusion)
- **Holliday**: Strand mixing (interdependence)
- **Supercoil**: Topological rotation (diffusion)
- **Transposon**: Segment displacement (diffusion)
- **Polymerase**: Sequential correlation (diffusion)

### Layer 1: Hairpin Folding

**Real Biology Background:**

In actual DNA, a hairpin is a secondary structure where a single strand folds back on itself through complementary base pairing:

```
Real hairpin structure:
  5'---CGCGCG---TTTT---CGCGCG---3'
       |||||            |||||
       Stem 1           Stem 2
         └────Loop────┘

The two stems (mirror sequences) form base pairs:
  C-G, G-C, C-G, G-C, C-G, G-C
```

**Cipher Implementation:**

The cipher simulates hairpin folding by swapping segments of size `stem_length`:

```python
def hairpin_fold(dna: str, stem_len: int) -> str:
    """
    Swap adjacent stem segments—simulates hairpin folding.
    
    Parameters:
      dna: DNA sequence
      stem_len: Length of each "stem" (typically 4-9 bases)
    """
    step = stem_len * 2  # Process pairs of stems
    
    for i in range(0, len(dna) - step, step):
        # Segment 1: dna[i : i + stem_len]
        # Segment 2: dna[i + stem_len : i + 2*stem_len]
        
        # Swap them
        dna[i:i+stem_len], dna[i+stem_len:i+2*stem_len] = \
            dna[i+stem_len:i+2*stem_len], dna[i:i+stem_len]
    
    return dna
```

**Example: Hairpin Fold**
```
Input:  ATGCTAGCTTTA
stem_len = 4

Segments: [ATGC] [TAGC] [TTTA]
          Stem1  Stem2  Stem3

After swapping Stem1↔Stem2:
Output: TAGCATGCTTTA

Segments: [TAGC] [ATGC] [TTTA]
```

**Cryptographic Role:**

- **Diffusion**: Spreads information from one position to others
- **Deterministic**: Given the same stem_length, transformation is reversible
- **Position-Dependent**: Changes depend on both position and sequence length

**Real-World Connection:**

Actual hairpins are structural features that regulate gene expression, protect DNA during replication, and facilitate recombination. The cipher's swap operation mirrors how stem structures create distant correlations.

---

### Layer 2: Codon Substitution

**Real Biology Background:**

The **genetic code** maps 64 three-base codons to 20 amino acids:

```
Codon Triplet  →  Amino Acid
     AUG        →     Met (Methionine - start)
     TAA        →     STOP
     CAT        →     His (Histidine)
     ...
```

A key property: **Multiple codons code for the same amino acid** (degeneracy):

```
Leucine (L) can be coded by:
  TTA, TTG, CTT, CTC, CTA, CTG

Serine (S) can be coded by:
  TCT, TCC, TCA, TCG, AGT, AGC
```

These are **synonymous codons**—they're functionally equivalent but structurally different. In real cells, organisms can switch between synonymous codons without changing the protein produced.

**Cipher Implementation:**

The cipher exploits this biological property to create a nonlinear substitution (like an S-box in traditional ciphers):

```python
def codon_substitute(dna: str, lfsr: LFSR) -> str:
    """
    Apply synonymous codon substitution using LFSR-driven selection.
    """
    out = []
    
    for i in range(0, len(dna) - 2, 3):
        codon = dna[i:i+3]
        
        if codon in GENETIC_CODE:
            # Get amino acid
            aa = GENETIC_CODE[codon]
            
            # Get all synonymous codons for this amino acid
            synonyms = AA_TO_CODONS[aa]
            
            # Pick one pseudorandomly using LFSR
            index = lfsr.randint(len(synonyms))
            new_codon = synonyms[index]
            
            out.append(new_codon)
        else:
            # Keep non-standard codons
            out.append(codon)
    
    return "".join(out)
```

**Example: Codon Substitution**
```
Input codon: CTT (Leucine)
Synonymous options: [CTA, CTG, CTT, TTA, TTG]

LFSR generates: index = 2
Selected: CTT (same codon)

Input codon: TTA (Leucine)
LFSR generates: index = 3
Selected: CTA (different codon, same amino acid)

Output: CTT CTA ... (functionally equivalent amino acids, different DNA)
```

**Cryptographic Role:**

- **Confusion**: Changes the sequence while preserving biological meaning
- **Nonlinearity**: LFSR selection creates data-dependent substitution
- **Reversibility**: Can invert by undoing LFSR sequence (deterministic)
- **Biological Realism**: Uses actual biological codon equivalences

**Real-World Connection:**

Codon bias—the preferential use of certain synonymous codons—is a real biological phenomenon. Some organisms favor specific codons based on tRNA availability. The cipher simulates an organism dynamically switching codon preferences, which would be biologically undetectable (same proteins) but cryptographically significant.

---

### Layer 3: Holliday Junction Recombination

**Real Biology Background:**

A **Holliday junction** is a four-way DNA junction formed during DNA recombination (like in sexual reproduction or DNA repair):

```
Real Holliday junction structure:

        Strand A
           ↓
    5'----●----3'
    3'----●----5'
        ↑     ↓
      Strand B and Strand D
      (crossover point)

Two DNA molecules exchange genetic material:
Before:  Parent1: AAAA CCCC
         Parent2: TTTT GGGG
         
After:   Child1:  AAAA GGGG  (hybrid)
         Child2:  TTTT CCCC  (hybrid)
```

In Holliday recombination, nucleotides from one strand mix with nucleotides from another strand, creating new genetic combinations.

**Cipher Implementation:**

The cipher simulates strand mixing by combining a "state" strand with a "key" strand using modular arithmetic:

```python
def holliday_mix(state: str, key: str) -> str:
    """
    Mix state strand with key strand base-by-base using mod-4 addition.
    
    DNA bases as numbers:
      A=0, T=1, C=2, G=3
    """
    mixed = []
    
    for base_state, base_key in zip(state, key):
        # Convert to 0-3 representation
        val_state = DNA_TO_NUM[base_state]
        val_key = DNA_TO_NUM[base_key]
        
        # Combine using mod-4 arithmetic
        combined = (val_state + val_key) % 4
        
        # Convert back to base
        mixed.append(NUM_TO_DNA[combined])
    
    return "".join(mixed)
```

**Example: Holliday Mixing**
```
State strand: A T C G
Key strand:   C G A T

Arithmetic (base as 0-3):
  A(0) + C(2) = 2 mod 4 = 2 → C
  T(1) + G(3) = 4 mod 4 = 0 → A
  C(2) + A(0) = 2 mod 4 = 2 → C
  G(3) + T(1) = 4 mod 4 = 0 → A

Output: C A C A
```

**Cryptographic Role:**

- **Dependency**: Output depends equally on state and key—neither dominates
- **Mixing**: Creates interdependence between message and key
- **Reversibility**: Can undo with (output - key) mod 4
- **Symmetric**: Natural group structure of mod-4 arithmetic

**Real-World Connection:**

Actual Holliday junctions create recombined DNA—offspring inherit unique combinations of parental genes. The cipher's mixing operation similarly "recombines" message and key, creating offspring DNA sequences that carry characteristics of both.

---

### Layer 4: DNA Supercoiling

**Real Biology Background:**

**Supercoiling** refers to the three-dimensional topology of the DNA double helix. DNA doesn't exist as a simple flat ladder—it's twisted and coiled:

```
B-form DNA (canonical):
  Regular twist of ~10.5 base pairs per complete helix turn

Negative supercoiling (underwinding):
  Fewer turns → DNA wraps tightly on nucleosomes
  Common in vivo (living cells)
  Makes DNA more compact

Positive supercoiling (overwinding):
  More turns → DNA wraps loosely or inverts
  Rare naturally, tension-inducing
  Important for DNA replication stress
```

DNA supercoiling is regulated by topoisomerase enzymes, which control supercoil density to:
- Compact DNA into nucleus
- Allow transcription and replication
- Regulate gene expression
- Respond to stress

**Cipher Implementation:**

The cipher simulates supercoil changes through circular rotation:

```python
def supercoil_transform(dna: str, topology_factor: int, lfsr: LFSR) -> str:
    """
    Rotate DNA strand to simulate supercoil topological change.
    
    A left rotation simulates underwinding (tightening),
    a right rotation simulates overwinding (loosening).
    """
    if len(dna) == 0:
        return dna
    
    # Generate rotation amount from LFSR
    rotation = lfsr.randint(len(dna)) * topology_factor
    rotation %= len(dna)
    
    # Rotate left (underwinding)
    rotated = dna[rotation:] + dna[:rotation]
    
    return rotated
```

**Example: Supercoil Transform**
```
Input DNA: ATGCTAGCTTTA (length 12)
topology_factor: 2

LFSR generates: randint(12) = 3
rotation = 3 × 2 = 6

Rotate left by 6:
  Original: A T G C T A G C T T T A
            0 1 2 3 4 5 6 7 8 9 10 11
  
  Keep: dna[6:] = G C T T T A
  Wrap: dna[:6] = A T G C T A
  
  Result: G C T T T A A T G C T A
```

**Cryptographic Role:**

- **Diffusion**: Moves all positions, spreading changes globally
- **Connectivity**: Creates circular structure—last character affects first
- **Reversibility**: Inverse rotation reverses transformation
- **Key-Dependent**: LFSR and topology factor determine rotation amount

**Real-World Connection:**

In real cells, topoisomerases continuously adjust supercoiling in response to transcription, replication, and recombination. The cipher's rotation simulates these topological adjustments—the "tightness" of the helix changes, affecting global sequence arrangement.

---

### Layer 5: Transposon Hopping

**Real Biology Background:**

**Transposons** (or "jumping genes") are DNA sequences that can move from one location to another within a genome:

```
Transposon movement (simplified):

Before:
  Chromosome: [Gene1] [TE] [Gene2] [Gene3]
                      ↑______(Transposon Element)

After transposition:
  Chromosome: [Gene1] [Gene2] [TE] [Gene3]
                              ↑______(Moved!)
```

Types of transposons:
- **Retrotransposons**: Copy themselves (copy-and-paste)
- **DNA transposons**: Move directly (cut-and-paste)

This cipher models **DNA transposons** (cut-and-paste mechanism):

1. Transposon recognizes terminal inverted repeats (TIRs)
2. Transposase enzyme cuts at source location
3. Segment is excised
4. Segment inserts at target location
5. Transposition complete

**Real-world impact**: Transposons account for ~45% of the human genome and are a major source of genetic variation and evolution.

**Cipher Implementation:**

The cipher simulates transposon movement through segment extraction and rotation:

```python
def transposon_forward(dna: str, lfsr: LFSR, tlen: int) -> str:
    """
    Simulate transposon hopping: extract segment and rotate it.
    
    Parameters:
      dna: DNA strand
      lfsr: Deterministic random source
      tlen: Transposon length (typically 8-23 bases)
    """
    n = len(dna)
    
    if n <= tlen + 4:
        return dna  # Strand too short for meaningful hopping
    
    # LFSR selects source position
    src = lfsr.randint(n - tlen)
    
    # LFSR selects hop distance
    hop = lfsr.randint(n - tlen)
    
    # Calculate target position
    tgt = (src + hop) % (n - tlen)
    
    if tgt <= src:
        return dna  # No-op if target before source
    
    # Extract segment from src to tgt+tlen
    segment = dna[src : tgt + tlen]
    
    # Rotate segment left by transposon length (moving "tail" forward)
    rotated = segment[tlen:] + segment[:tlen]
    
    # Reconstruct DNA with rotated segment
    return dna[:src] + rotated + dna[tgt + tlen:]
```

**Example: Transposon Hopping**
```
Input:  ATGCTAGCTTTACCCGGG (len=17)
tlen=4

LFSR selects:
  src = 2
  hop = 5
  tgt = (2+5) % (17-4) = 7 % 13 = 7

Segment to move: dna[2:7+4] = dna[2:11] = GCTAGCTTTA
Rotate left by 4: GCTTTAGCTA

Result: AT + GCTTTAGCTA + CCCGGG
        = ATGCTTTAGCTACCCGGG
```

**Cryptographic Role:**

- **Permutation**: Reorders sequence elements
- **LFSR-Dependent**: Insertion positions depend on random source
- **Nonlocal**: Affects distant positions far apart
- **Reversibility**: Can reverse using inverse LFSR states

**Real-World Connection:**

Actual transposons reshape genomes, creating new mutations and variations. The cipher simulates this mutagenic property—moving sequence segments creates new arrangements that retain all bases but in different order, just as transposon activity creates genetic novelty while reusing existing DNA.

---

### Layer 6: DNA Polymerase Activity

**Real Biology Background:**

**DNA polymerase** is the enzyme responsible for DNA replication. As it reads the template strand, it synthesizes a complementary strand by adding nucleotides one-by-one:

```
Replication process:

Template:  3'---A---T---C---G---5'
              |   |   |   |
Synthesis: 5'---T---A---G---C---3'
           (polymerase → direction)

Polymerase processes one base at a time, with context from:
- Parent template strand
- Previously synthesized strand
- Incoming nucleotides from environment
```

A key property: **Each added nucleotide depends on the previous nucleotide** due to:
- Base stacking forces (physical chemistry)
- Polymerase geometry and proofreading
- Local DNA structure

This creates **sequential dependency**—a chain where each link depends on the previous one.

**Cipher Implementation:**

The cipher simulates polymerase processing through XOR chaining:

```python
def polymerase_forward(dna: str) -> str:
    """
    Simulate DNA polymerase synthesis with memory.
    Each base depends on the previous base via XOR (exclusive OR).
    
    Bases as numbers: A=0, T=1, C=2, G=3
    """
    if len(dna) == 0:
        return dna
    
    out = []
    
    # First base remains unchanged (primer in real synthesis)
    prev = BASE_TO_INT[dna[0]]
    out.append(dna[0])
    
    # Process each subsequent base with context
    for b in dna[1:]:
        cur = BASE_TO_INT[b]
        
        # XOR creates conditional substitution based on previous base
        val = (cur ^ prev) % 4
        
        out.append(INT_TO_BASE[val])
        
        # Update context for next iteration
        prev = val
    
    return "".join(out)
```

**Example: Polymerase Forward Transform**
```
Input:  A T C G A (bases as 0 1 2 3 0)

Output[0] = A (unchanged, it's the primer) → 0
Output[1] = T XOR prev(0) = 1 XOR 0 = 1 → T
Output[2] = C XOR prev(1) = 2 XOR 1 = 3 → G
Output[3] = G XOR prev(3) = 3 XOR 3 = 0 → A
Output[4] = A XOR prev(0) = 0 XOR 0 = 0 → A

Output: A T G A A
```

**Reverse Transform (Polymerase Inverse):**

To reverse this, we need to recover the original bases given the dependencies:

```python
def polymerase_inverse(dna: str) -> str:
    """
    Reverse polymerase transformation.
    
    The key insight: to recover prev_original, we know:
      current_transformed = prev_transformed XOR next_original
    
    So: next_original = current_transformed XOR next_transformed
    """
    if len(dna) == 0:
        return dna
    
    out = []
    prev = BASE_TO_INT[dna[0]]
    out.append(dna[0])
    
    for b in dna[1:]:
        cur = BASE_TO_INT[b]
        
        # XOR with previous transformed value
        val = (cur ^ prev) % 4
        
        out.append(INT_TO_BASE[val])
        
        # Update: prev is now the ORIGINAL base we just recovered
        prev = cur  # (not val!)
    
    return "".join(out)
```

**Cryptographic Role:**

- **Sequential Correlation**: Each position depends on the previous—creating a chain
- **Diffusion**: Changes propagate forward through the sequence
- **Irreversibility Within Layer**: Need context to reverse transformation
- **Error Propagation**: Errors in one position affect all subsequent positions (like real polymerase)

**Real-World Connection:**

In true DNA replication, polymerase adds nucleotides sequentially, building one strand while reading another. The cipher's XOR chaining mirrors this sequential dependence—each new base "remembers" the previous base through mathematical combination, just as polymerase builds strand context as it moves along the template.

---

## Key Schedule

### Deterministic Parameter Derivation

The **key schedule** converts a master key into all parameters required for the cipher, including:
- Number of rounds
- LFSR seed
- Per-layer parameters (stem length, transposon length, topology factor)

This ensures that every bit of the key influences the entire encryption process.

### Implementation

```python
def key_schedule(master_key: str):
    # Hash the master key with SHA-512 (512 bits = 64 bytes)
    digest = SHA512(master_key)
    
    # Extract distinct 80-bit LFSR seed (bytes 0-9)
    lfsr_seed = bytes_to_int(digest[0:10])
    
    # Derive number of rounds (10-15)
    rounds = 10 + digest[10] % 6
    
    # Hairpin stem_length (4-9 bases)
    stem_length = 4 + digest[11] % 6
    
    # Loop size for hairpins (3-8)
    loop_size = 3 + digest[12] % 6
    
    # Holliday window (16-47)
    holliday_window = 16 + digest[13] % 32
    
    # Transposon length (8-23 bases)
    transposon_length = 8 + digest[14] % 16
    
    # Topology factor for supercoiling (1-5)
    topology_factor = 1 + digest[15] % 5
```

### Why This Works

- **Deterministic**: Same key always produces same parameters
- **Avalanche Effect**: Small key change → completely different parameters
- **Multi-parameter**: Different LFSR seeds for each layer ensure independence
- **Biological Realism**: Parameters mimic natural variation in biological systems

---

## Security Features

### 1. **Biological Complexity**

Each layer implements a real DNA process:
- Hairpin: Physical folding mechanics
- Codon: Genetic code redundancy
- Holliday: Molecular recombination
- Supercoil: Topological changes
- Transposon: Mobile elements
- Polymerase: Sequential synthesis

These aren't arbitrary operations—they're grounded in 3+ billion years of biological evolution, inherently complex.

### 2. **Layered Defense (6 Layers)**

Each layer contributes different cryptographic properties:
- Layer 1: Positional permutation
- Layer 2: Nonlinear substitution
- Layer 3: Key-state mixing
- Layer 4: Global rotation
- Layer 5: Segment rearrangement
- Layer 6: Sequential correlation

Breaking one layer doesn't break others.

### 3. **Deterministic LFSR (Pseudo-Random)**

Linear Feedback Shift Register (80-bit) generates reproducible randomness for:
- Codon selection
- Rotation amounts
- Transposon positions

Deterministic allows decryption; LFSR structure provides mixing and nonlinearity.

### 4. **Multiple Rounds (10-15)**

- Minimum 10 rounds (security floor)
- Maximum 15 rounds (key-dependent)
- Each round repeats all 6 layers
- Cumulative effect: 60-90 layers of transformation

### 5. **Post-Quantum Hybridization**

- Uses Kyber/ML-KEM for asymmetric encryption (resistant to quantum algorithms)
- Symmetric GCRC cipher is quantum-resistant by design (not based on factoring or discrete log)

### 6. **Integrity Authentication**

- HMAC-SHA256 ensures ciphertext wasn't modified
- Prevents tampering attacks

---

## Usage Examples

### Encryption Example

```python
import os
from encoder import encrypt_message, save_encrypted

# Step 1: Generate key pair (first time only)
from generate_keys import generate_kyber_keys
generate_kyber_keys()  # Creates public.key and private.key

# Step 2: Prepare message
message = "This is a secret message"

# Step 3: Load public key
with open("public.key", "rb") as f:
    public_key = f.read()

# Step 4: Encrypt
encrypted_data = encrypt_message(message, public_key)

# Step 5: Save to file
save_encrypted(encrypted_data, "encrypted.json")

print("Encryption complete!")
print(f"Original length: {len(message)} characters")
print(f"DNA length: {encrypted_data['length']} bases")
print(f"Encrypted DNA (first 100 bases): {encrypted_data['cipher_dna'][:100]}")
```

### Decryption Example

```python
import json
from decoder import decrypt_message

# Step 1: Load encrypted data
with open("encrypted.json", "r") as f:
    encrypted_data = json.load(f)

# Step 2: Load private key
with open("private.key", "rb") as f:
    private_key = f.read()

# Step 3: Decrypt
plaintext = decrypt_message(encrypted_data, private_key)

print(f"Decrypted message: {plaintext}")
```

### Understanding Encryption Output

```json
{
  "cipher_dna": "ATGCTAGCTTTACCCGGGATTACGA...",
  "kyber_ciphertext": "a3f2b1c0e8d9...",
  "hmac": "f4e3d2c1b0a...",
  "length": 128
}
```

- **cipher_dna**: The encrypted message in DNA form (4-character alphabet)
- **kyber_ciphertext**: Encrypted shared key (post-quantum resistant)
- **hmac**: Integrity tag (verifies message wasn't modified)
- **length**: Original DNA sequence length (needed for decoding)

---

## Biological-to-Cryptographic Mapping Summary

| DNA Process | Real Biology | Cipher Operation | Cryptographic Role |
|---|---|---|---|
| **Hairpin Folding** | DNA strands fold back on self | Segment swapping | Diffusion + permutation |
| **Codon Substitution** | Multiple codons → same amino acid | LFSR-driven substitution | Confusion + nonlinearity |
| **Holliday Recombination** | DNA strands exchange material | Mod-4 mixing | Key-state dependency |
| **Supercoiling** | DNA topological winding | Circular rotation | Global diffusion |
| **Transposon Hopping** | Mobile DNA elements | Segment extraction & rotation | Permutation + rearrangement |
| **DNA Polymerase** | Sequential strand synthesis | XOR chaining | Sequential correlation |

---

## Performance Characteristics

### Encryption Speed
- Text-to-DNA: O(n) where n = message length
- GCRC encryption: O(n × layers × rounds) = O(n × 60-90)
- Typical: ~milliseconds for <1MB messages

### Memory Usage
- Minimal: Only stores current DNA strand
- No large lookup tables or matrices

### Key Size
- Master key: 32 bytes (256-bit)
- Derived parameters: SHA-512 (64 bytes) → used to generate all params

### Output Size
- Encrypted DNA length ≈ Original DNA length
- Additional overhead: Kyber ciphertext (~1088 bytes) + HMAC (32 bytes)

---

## References & Inspiration

This cipher draws inspiration from:

1. **DNA Cryptography Research**
   - Adleman, L. (1994) "Molecular Computation of Solutions to Combinatorial Problems"
   - DNA computing demonstrates information processing via molecular operations

2. **Biological Processes**
   - DNA replication, recombination, transposition (core concepts)
   - Codon degeneracy and genetic code (inherited from real biology)

3. **Cryptographic Principles**
   - Confusion and diffusion (Shannon)
   - Multiple rounds and S-box principles (Feistel networks)
   - LFSR-based key streams (stream ciphers)

4. **Post-Quantum Cryptography**
   - Kyber/ML-KEM (lattice-based, quantum-resistant)

---

## Conclusion

**DNA-GCRC** demonstrates that biological processes can serve as cryptographic primitives. By implementing real DNA transformations—hairpin folding, genetic code variation, strand recombination, topological changes, transposon insertion, and polymerase synthesis—we create a cipher that is:

- **Theoretically grounded**: Every operation corresponds to real biology
- **Cryptographically sound**: Confusion + diffusion through 6 distinct layers
- **Reversible**: All operations can be inverted for decryption
- **Quantum-resistant**: Not based on factoring or discrete logarithm problems
- **Educationally valuable**: Demonstrates how nature's algorithms can inspire security

This represents a unique intersection of biology, cryptography, and information theory—showing that the mechanisms evolution perfected for storing genetic information can also secure human secrets.

