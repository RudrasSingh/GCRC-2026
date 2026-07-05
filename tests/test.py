"""
GCRC Cipher — NIST SP 800-22 Aligned Test Suite
================================================
Implements all 15 NIST statistical tests plus cipher-specific
metrics (avalanche, NPCR/UACI, LAT, key sensitivity).

Each test returns a p-value. The significance threshold is 0.01.
A sequence passes if p >= 0.01.
"""

import os
import sys
import math
import random
import struct
import numpy as np
from collections import Counter
from scipy.special import erfc, gammaincc
from scipy.stats import chi2 as scipy_chi2

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import text_to_dna


# ──────────────────────────────────────────────
# CONSTANTS / HELPERS
# ──────────────────────────────────────────────

BASE_TO_INT = {"A": 0, "T": 1, "C": 2, "G": 3}
ALPHA = 0.01          # NIST significance level
TRIALS = 5_000        # number of cipher samples
NIST_SEQ_LEN = 1_000  # bits per NIST sequence (min recommended: 100)


def dna_to_bits(dna: str) -> list[int]:
    bits = []
    for b in dna:
        v = BASE_TO_INT[b]
        bits.append((v >> 1) & 1)
        bits.append(v & 1)
    return bits


def dna_to_ints(dna: str) -> list[int]:
    return [BASE_TO_INT[b] for b in dna]


def bits_to_pm1(bits: list[int]) -> list[int]:
    """Convert {0,1} sequence to {-1,+1} for NIST tests."""
    return [1 if b else -1 for b in bits]


def random_message() -> str:
    return os.urandom(32).hex()


def _pad_or_trim(bits: list[int], length: int) -> list[int]:
    if len(bits) >= length:
        return bits[:length]
    return bits + [0] * (length - len(bits))


# ──────────────────────────────────────────────
# NIST SP 800-22  —  ALL 15 TESTS
# ──────────────────────────────────────────────

def nist_frequency_monobit(bits: list[int]) -> float:
    """Test 1: Frequency (Monobit)."""
    n = len(bits)
    s = abs(sum(bits_to_pm1(bits))) / math.sqrt(n)
    return erfc(s / math.sqrt(2))


def nist_block_frequency(bits: list[int], M: int = 128) -> float:
    """Test 2: Frequency within a Block."""
    n = len(bits)
    N = n // M
    if N == 0:
        return 0.0
    chi_sq = 0.0
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        pi = sum(block) / M
        chi_sq += (pi - 0.5) ** 2
    chi_sq *= 4 * M
    return gammaincc(N / 2, chi_sq / 2)


def nist_runs(bits: list[int]) -> float:
    """Test 3: Runs."""
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0
    vn = sum(1 for i in range(n - 1) if bits[i] != bits[i + 1]) + 1
    num = abs(vn - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    return erfc(num / den)


def nist_longest_run_of_ones(bits: list[int]) -> float:
    """Test 4: Longest Run of Ones in a Block."""
    n = len(bits)
    if n < 128:
        return 0.0

    # Use M=8, K=3, N=16 parameters (smallest valid set per NIST)
    M, K, N = 8, 3, 16
    pi = [0.2148, 0.3672, 0.2305, 0.1875]

    V = [0] * (K + 1)
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        max_run = cur = 0
        for b in block:
            if b == 1:
                cur += 1
                max_run = max(max_run, cur)
            else:
                cur = 0
        idx = min(max_run, K)
        V[idx] += 1

    chi_sq = sum((V[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(K + 1))
    return gammaincc(K / 2, chi_sq / 2)


def nist_binary_matrix_rank(bits: list[int], M: int = 32, Q: int = 32) -> float:
    """Test 5: Binary Matrix Rank."""
    n = len(bits)
    N = n // (M * Q)
    if N == 0:
        return 0.0

    def matrix_rank(mat):
        m = [row[:] for row in mat]
        rank = 0
        for col in range(Q):
            pivot = None
            for row in range(rank, M):
                if m[row][col]:
                    pivot = row
                    break
            if pivot is None:
                continue
            m[rank], m[pivot] = m[pivot], m[rank]
            for row in range(M):
                if row != rank and m[row][col]:
                    m[row] = [m[row][j] ^ m[rank][j] for j in range(Q)]
            rank += 1
        return rank

    FM = FMm1 = rest = 0
    for k in range(N):
        block = bits[k * M * Q:(k + 1) * M * Q]
        mat = [[block[i * Q + j] for j in range(Q)] for i in range(M)]
        r = matrix_rank(mat)
        if r == M:
            FM += 1
        elif r == M - 1:
            FMm1 += 1
        else:
            rest += 1

    p0 = 0.2888
    p1 = 0.5776
    p2 = 1 - p0 - p1
    chi_sq = ((FM - p0 * N) ** 2 / (p0 * N) +
              (FMm1 - p1 * N) ** 2 / (p1 * N) +
              (rest - p2 * N) ** 2 / (p2 * N))
    return math.exp(-chi_sq / 2)


def nist_dft_spectral(bits: list[int]) -> float:
    """Test 6: Discrete Fourier Transform (Spectral)."""
    n = len(bits)
    x = bits_to_pm1(bits)
    f = np.fft.fft(x)
    magnitudes = np.abs(f[:n // 2])
    T = math.sqrt(math.log(1 / 0.05) * n)
    n0 = 0.95 * n / 2
    n1 = sum(1 for m in magnitudes if m < T)
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4)
    return erfc(abs(d) / math.sqrt(2))


def nist_non_overlapping_template(bits: list[int], template: list[int] | None = None) -> float:
    """Test 7: Non-overlapping Template Matching (m=9 default pattern)."""
    if template is None:
        template = [0, 0, 0, 0, 0, 0, 0, 0, 1]
    m = len(template)
    n = len(bits)
    M = 8
    N = n // M
    if N == 0:
        return 0.0
    mu = (M - m + 1) / (2 ** m)
    sigma2 = M * (1 / 2 ** m - (2 * m - 1) / 2 ** (2 * m))
    W = []
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        count = j = 0
        while j <= M - m:
            if block[j:j + m] == template:
                count += 1
                j += m
            else:
                j += 1
        W.append(count)
    chi_sq = sum((w - mu) ** 2 / sigma2 for w in W)
    return gammaincc(N / 2, chi_sq / 2)


def nist_overlapping_template(bits: list[int]) -> float:
    """Test 8: Overlapping Template Matching (pattern = 1^9)."""
    template = [1] * 9
    m = len(template)
    n = len(bits)
    M = 1032
    N = n // M
    if N == 0:
        return 0.0
    K = 5
    pi = [0.364091, 0.185659, 0.139381, 0.100571, 0.0704323, 0.139865]
    V = [0] * (K + 1)
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        count = sum(1 for j in range(M - m + 1)
                    if block[j:j + m] == template)
        V[min(count, K)] += 1
    chi_sq = sum((V[i] - N * pi[i]) ** 2 / (N * pi[i])
                 for i in range(K + 1) if pi[i] > 0)
    return gammaincc(K / 2, chi_sq / 2)


def nist_maurers_universal(bits: list[int], L: int = 7, Q: int = 1280) -> float:
    """Test 9: Maurer's Universal Statistical."""
    n = len(bits)
    if n < (Q + 1000) * L:
        return 0.0
    table = {}
    for i in range(Q):
        key = tuple(bits[i * L:(i + 1) * L])
        table[key] = i + 1
    fn = 0.0
    K = (n // L) - Q
    for i in range(Q, Q + K):
        key = tuple(bits[i * L:(i + 1) * L])
        fn += math.log2(i + 1 - table.get(key, 1))
        table[key] = i + 1
    fn /= K
    # Expected values for L=7
    expected_L7 = {7: (6.1962507, 3.125)}
    if L not in expected_L7:
        return 0.0
    expected_value, variance = expected_L7[L]
    c = 0.7 - 0.8 / L + (4 + 32 / L) * (K ** (-3 / L)) / 15
    sigma = c * math.sqrt(variance / K)
    z = (fn - expected_value) / sigma
    return erfc(abs(z) / math.sqrt(2))


def nist_linear_complexity(bits: list[int], M: int = 500) -> float:
    """Test 10: Linear Complexity."""
    n = len(bits)
    N = n // M
    if N == 0:
        return 0.0

    def berlekamp_massey(seq):
        n = len(seq)
        c = [0] * n
        b = [0] * n
        c[0] = b[0] = 1
        L = r = 0
        for i in range(n):
            d = seq[i]
            for j in range(1, L + 1):
                d ^= c[j] & seq[i - j]
            if d == 0:
                r += 1
            else:
                t = c[:]
                for j in range(r + 1, n):
                    c[j] ^= b[j - r - 1]
                if 2 * L <= i:
                    L = i + 1 - L
                    b = t
                    r = 0
                else:
                    r += 1
        return L

    mu = M / 2 + (9 + (-1) ** (M + 1)) / 36 - (M / 3 + 2 / 9) / 2 ** M
    T = [berlekamp_massey(list(bits[i * M:(i + 1) * M])) for i in range(N)]
    K = 6
    pi = [0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833]
    V = [0] * (K + 1)
    for Lc in T:
        t = (-1) ** M * (Lc - mu) + 2 / 9
        if t <= -2.5:
            V[0] += 1
        elif t <= -1.5:
            V[1] += 1
        elif t <= -0.5:
            V[2] += 1
        elif t <= 0.5:
            V[3] += 1
        elif t <= 1.5:
            V[4] += 1
        elif t <= 2.5:
            V[5] += 1
        else:
            V[6] += 1
    chi_sq = sum((V[i] - N * pi[i]) ** 2 / (N * pi[i])
                 for i in range(K + 1) if pi[i] > 0)
    return gammaincc(K / 2, chi_sq / 2)


def nist_serial(bits: list[int], m: int = 16) -> tuple[float, float]:
    """Test 11: Serial — returns (p1, p2)."""
    n = len(bits)

    def psi_sq(m):
        if m == 0:
            return 0.0
        counts = Counter(tuple(bits[i:i + m]) for i in range(n))
        return 2 ** m / n * sum(v ** 2 for v in counts.values()) - n

    p2m = psi_sq(m)
    p2m1 = psi_sq(m - 1)
    p2m2 = psi_sq(m - 2)
    d1 = p2m - p2m1
    d2 = p2m - 2 * p2m1 + p2m2
    p1 = gammaincc(2 ** (m - 2), d1 / 2)
    p2 = gammaincc(2 ** (m - 3), d2 / 2)
    return p1, p2


def nist_approximate_entropy(bits: list[int], m: int = 10) -> float:
    """Test 12: Approximate Entropy."""
    n = len(bits)

    def phi(m_):
        if m_ == 0:
            return 0.0
        counts = Counter(
            tuple(bits[(i + j) % n] for j in range(m_))
            for i in range(n)
        )
        return sum(v / n * math.log(v / n) for v in counts.values())

    apen = phi(m) - phi(m + 1)
    chi_sq = 2 * n * (math.log(2) - apen)
    return gammaincc(2 ** (m - 1), chi_sq / 2)


def nist_cumulative_sums(bits: list[int]) -> tuple[float, float]:
    """Test 13: Cumulative Sums — forward and backward."""
    n = len(bits)
    x = bits_to_pm1(bits)

    def _p(S, n):
        z = max(abs(s) for s in S)
        sq = math.sqrt(n)
        k_start = int((-n / z + 1) / 4)
        k_end = int((n / z - 1) / 4)

        def norm_cdf(v):
            return 0.5 * erfc(-v / math.sqrt(2))

        total = 0.0
        for k in range(k_start, k_end + 1):
            total += norm_cdf((4 * k + 1) * z / sq) - norm_cdf((4 * k - 1) * z / sq)
        total2 = 0.0
        for k in range(k_start - 1, k_end + 1):
            total2 += norm_cdf((4 * k + 3) * z / sq) - norm_cdf((4 * k + 1) * z / sq)
        return 1 - total + total2

    fwd = list(np.cumsum(x))
    bwd = list(np.cumsum(x[::-1]))
    return _p(fwd, n), _p(bwd, n)


def nist_random_excursions(bits: list[int]) -> dict[int, float]:
    """Test 14: Random Excursions."""
    x = bits_to_pm1(bits)
    S = list(np.cumsum(x))
    S = [0] + S + [0]
    cycles = []
    start = 0
    for i in range(1, len(S)):
        if S[i] == 0:
            cycles.append(S[start:i + 1])
            start = i
    J = len(cycles)
    if J < 500:
        return {}

    states = [-4, -3, -2, -1, 1, 2, 3, 4]
    pi_table = {
        1: [0.5, 0.25, 0.125, 0.0625, 0.0312, 0.0312],
        2: [0.75, 0.0625, 0.0469, 0.0352, 0.0264, 0.0791],
        3: [0.8333, 0.0278, 0.0231, 0.0193, 0.0161, 0.0804],
        4: [0.875, 0.0156, 0.0137, 0.012, 0.0105, 0.0733],
    }
    results = {}
    for state in states:
        abs_s = abs(state)
        pi = pi_table.get(abs_s, pi_table[4])
        K = 5
        V = [0] * (K + 1)
        for cycle in cycles:
            count = sum(1 for v in cycle if v == state)
            V[min(count, K)] += 1
        chi_sq = sum((V[k] - J * pi[k]) ** 2 / (J * pi[k])
                     for k in range(K + 1) if pi[k] > 0)
        results[state] = gammaincc(K / 2, chi_sq / 2)
    return results


def nist_random_excursions_variant(bits: list[int]) -> dict[int, float]:
    """Test 15: Random Excursions Variant."""
    x = bits_to_pm1(bits)
    S = list(np.cumsum(x))
    S_aug = [0] + S + [0]
    J = S_aug.count(0) - 1
    if J < 500:
        return {}
    results = {}
    for state in range(-9, 10):
        if state == 0:
            continue
        xi = sum(1 for v in S if v == state)
        denom = math.sqrt(2 * J * (4 * abs(state) - 2))
        if denom == 0:
            continue
        p = erfc(abs(xi - J) / denom)
        results[state] = p
    return results


# ──────────────────────────────────────────────
# CIPHER-SPECIFIC METRICS
# ──────────────────────────────────────────────

def avalanche_coefficient(b1: list[int], b2: list[int]) -> float:
    diff = sum(x ^ y for x, y in zip(b1, b2))
    return diff / len(b1)


def npcr_uaci(c1: str, c2: str) -> tuple[float, float]:
    a = dna_to_ints(c1)
    b = dna_to_ints(c2)
    n = len(a)
    npcr = sum(1 for i in range(n) if a[i] != b[i]) / n
    uaci = sum(abs(a[i] - b[i]) for i in range(n)) / (3 * n)
    return npcr, uaci


def compute_lat() -> np.ndarray:
    """Linear Approximation Table for the internal S-box."""
    sbox = [6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11]
    size = len(sbox)
    lat = np.zeros((size, size))
    for a in range(size):
        for b in range(size):
            bias = 0
            for x in range(size):
                ip = bin(a & x).count("1") % 2
                op = bin(b & sbox[x]).count("1") % 2
                bias += 1 if ip == op else -1
            lat[a][b] = bias
    return lat


def round_avalanche(cipher, dna: str) -> list[float]:
    trace1 = cipher.encrypt_with_trace(dna)
    bits = dna_to_bits(dna)
    flip = random.randint(0, len(bits) - 1)
    bits[flip] ^= 1
    dna2 = "".join(["ATCG"[(bits[i] << 1) | bits[i + 1]] for i in range(0, len(bits), 2)])
    trace2 = cipher.encrypt_with_trace(dna2)
    result = []
    for r in range(len(trace1)):
        b1 = dna_to_bits(trace1[r])
        b2 = dna_to_bits(trace2[r])
        diff = sum(x ^ y for x, y in zip(b1, b2))
        result.append(diff / len(b1))
    return result


def shannon_entropy(bits: list[int]) -> float:
    p = sum(bits) / len(bits)
    if p in (0.0, 1.0):
        return 0.0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


# ──────────────────────────────────────────────
# RESULT REPORTING
# ──────────────────────────────────────────────

def fmt_result(p: float) -> str:
    status = "PASS" if p >= ALPHA else "FAIL"
    return f"{p:.6f}  [{status}]"


def print_section(title: str):
    print()
    print("=" * 64)
    print(f"  {title}")
    print("=" * 64)


def print_row(label: str, value: str, width: int = 42):
    print(f"  {label:<{width}} {value}")


# ──────────────────────────────────────────────
# MAIN TEST SUITE
# ──────────────────────────────────────────────

def run_suite():
    cipher  = GCRC("test-key")
    cipher2 = GCRC("test-keY")   # one-character key difference

    # ── accumulate raw data ──────────────────────────────────────
    all_bits:      list[int]   = []
    avalanche:     list[float] = []
    key_avalanche: list[float] = []
    npcr_vals:     list[float] = []
    uaci_vals:     list[float] = []
    linear_matches: int        = 0

    rd_samples: list[list[float]] = []
    re_samples: list[list[float]] = []

    print(f"Running {TRIALS} cipher trials…", flush=True)

    for i in range(TRIALS):
        if (i + 1) % 500 == 0:
            print(f"  {i + 1}/{TRIALS}", flush=True)

        msg  = random_message()
        dna  = text_to_dna(msg)
        ct1  = cipher.encrypt(dna)
        b1   = dna_to_bits(ct1)

        # ── plaintext avalanche ──────────────────────────────────
        bits = dna_to_bits(dna)
        flip = random.randint(0, len(bits) - 1)
        bits[flip] ^= 1
        dna2 = "".join(["ATCG"[(bits[j] << 1) | bits[j + 1]] for j in range(0, len(bits), 2)])
        ct2  = cipher.encrypt(dna2)
        b2   = dna_to_bits(ct2)
        avalanche.append(avalanche_coefficient(b1, b2))

        # ── key avalanche ────────────────────────────────────────
        ct_key = cipher2.encrypt(dna)
        b3     = dna_to_bits(ct_key)
        key_avalanche.append(avalanche_coefficient(b1, b3))

        # ── linear bias proxy ────────────────────────────────────
        lhs = b1[0] ^ b1[5] ^ b1[9]
        rhs = b2[3] ^ b2[7] ^ b2[12]
        if lhs == rhs:
            linear_matches += 1

        # ── NPCR / UACI ──────────────────────────────────────────
        n, u = npcr_uaci(ct1, ct2)
        npcr_vals.append(n)
        uaci_vals.append(u)

        # ── collect bits for NIST tests ──────────────────────────
        all_bits.extend(b1)

        # ── round-level samples (first 50 trials only) ───────────
        if len(rd_samples) < 50:
            rd_samples.append(round_avalanche(cipher, dna))
            re_sample = [shannon_entropy(dna_to_bits(x))
                         for x in cipher.encrypt_with_trace(dna)]
            re_samples.append(re_sample)

    # ── prepare NIST bit sequence ────────────────────────────────
    seq = _pad_or_trim(all_bits, max(len(all_bits), NIST_SEQ_LEN * 100))
    # Use a fixed-length window for deterministic NIST calls
    nist_bits = seq[:20_000]

    # ────────────────────────────────────────────────────────────
    # REPORT
    # ────────────────────────────────────────────────────────────

    print_section("NIST SP 800-22 STATISTICAL TESTS")
    print(f"  Bit sequence length : {len(nist_bits):,}")
    print(f"  Significance level  : α = {ALPHA}")

    # Test 1
    p = nist_frequency_monobit(nist_bits)
    print_row("T01  Frequency (Monobit)", fmt_result(p))

    # Test 2
    p = nist_block_frequency(nist_bits)
    print_row("T02  Block Frequency (M=128)", fmt_result(p))

    # Test 3
    p = nist_runs(nist_bits)
    print_row("T03  Runs", fmt_result(p))

    # Test 4
    p = nist_longest_run_of_ones(nist_bits)
    print_row("T04  Longest Run of Ones", fmt_result(p))

    # Test 5
    p = nist_binary_matrix_rank(nist_bits)
    print_row("T05  Binary Matrix Rank", fmt_result(p))

    # Test 6
    p = nist_dft_spectral(nist_bits)
    print_row("T06  DFT Spectral", fmt_result(p))

    # Test 7
    p = nist_non_overlapping_template(nist_bits)
    print_row("T07  Non-overlapping Template", fmt_result(p))

    # Test 8
    p = nist_overlapping_template(nist_bits)
    print_row("T08  Overlapping Template", fmt_result(p))

    # Test 9
    p = nist_maurers_universal(nist_bits)
    print_row("T09  Maurer's Universal", fmt_result(p))

    # Test 10
    p = nist_linear_complexity(nist_bits)
    print_row("T10  Linear Complexity (M=500)", fmt_result(p))

    # Test 11
    p1, p2 = nist_serial(nist_bits)
    print_row("T11  Serial ψ²_m",   fmt_result(p1))
    print_row("T11  Serial ψ²_m-1", fmt_result(p2))

    # Test 12
    p = nist_approximate_entropy(nist_bits)
    print_row("T12  Approximate Entropy (m=10)", fmt_result(p))

    # Test 13
    p_fwd, p_bwd = nist_cumulative_sums(nist_bits)
    print_row("T13  Cumulative Sums (forward)",  fmt_result(p_fwd))
    print_row("T13  Cumulative Sums (backward)", fmt_result(p_bwd))

    # Test 14
    re_results = nist_random_excursions(nist_bits)
    if re_results:
        worst = min(re_results.values())
        best  = max(re_results.values())
        print_row("T14  Random Excursions (worst/best)",
                  f"{worst:.6f} / {best:.6f}")
    else:
        print_row("T14  Random Excursions", "N/A  (insufficient cycles)")

    # Test 15
    rev_results = nist_random_excursions_variant(nist_bits)
    if rev_results:
        worst = min(rev_results.values())
        best  = max(rev_results.values())
        print_row("T15  RE Variant (worst/best)",
                  f"{worst:.6f} / {best:.6f}")
    else:
        print_row("T15  RE Variant", "N/A  (insufficient cycles)")

    # ────────────────────────────────────────────────────────────
    print_section("CIPHER-SPECIFIC METRICS")
    print(f"  Samples : {TRIALS:,}")

    avg_av   = float(np.mean(avalanche))
    avg_kav  = float(np.mean(key_avalanche))
    avg_npcr = float(np.mean(npcr_vals))
    avg_uaci = float(np.mean(uaci_vals))
    lin_bias = abs(linear_matches / TRIALS - 0.5)
    bit_bal  = sum(all_bits) / len(all_bits)
    ent      = shannon_entropy(all_bits)

    # Ideal targets
    # Avalanche    → 0.500  (±0.05 acceptable)
    # NPCR         → 0.996  (≥0.99 acceptable)
    # UACI         → 0.334  (≥0.30 acceptable)
    # Bit balance  → 0.500  (|dev| < 0.01)
    # Entropy      → 1.000

    def cipher_status(val, ideal, tol):
        return "PASS" if abs(val - ideal) <= tol else "FAIL"

    av_s   = cipher_status(avg_av,   0.50, 0.05)
    kav_s  = cipher_status(avg_kav,  0.50, 0.05)
    npcr_s = "PASS" if avg_npcr >= 0.99  else "FAIL"
    uaci_s = "PASS" if avg_uaci >= 0.30  else "FAIL"
    lb_s   = "PASS" if lin_bias  <= 0.02 else "FAIL"
    bb_s   = cipher_status(bit_bal, 0.50, 0.01)
    ent_s  = cipher_status(ent,     1.00, 0.01)

    print_row("Plaintext Avalanche (ideal 0.5)",
              f"{avg_av:.6f}  [{av_s}]")
    print_row("Key Sensitivity Avalanche (ideal 0.5)",
              f"{avg_kav:.6f}  [{kav_s}]")
    print_row("NPCR (ideal ≥ 0.99)",
              f"{avg_npcr:.6f}  [{npcr_s}]")
    print_row("UACI (ideal ≥ 0.30)",
              f"{avg_uaci:.6f}  [{uaci_s}]")
    print_row("Linear Bias |p−0.5| (ideal ≤ 0.02)",
              f"{lin_bias:.6f}  [{lb_s}]")
    print_row("Bit Balance (ideal 0.5)",
              f"{bit_bal:.6f}  [{bb_s}]")
    print_row("Shannon Entropy (ideal 1.0)",
              f"{ent:.6f}  [{ent_s}]")

    # ────────────────────────────────────────────────────────────
    print_section("ROUND-LEVEL ANALYSIS  (50 samples)")

    if rd_samples:
        rd = np.mean(rd_samples, axis=0)
        re = np.mean(re_samples, axis=0)
        print("  Round  Diffusion   Entropy")
        print("  -----  ---------   -------")
        for idx in range(len(rd)):
            print(f"  R{idx + 1:02d}    {rd[idx]:.4f}      {re[idx]:.4f}")

    # ────────────────────────────────────────────────────────────
    print_section("LINEAR APPROXIMATION TABLE  (S-box)")

    lat = compute_lat()
    max_bias    = float(np.max(np.abs(lat[1:, 1:])))
    nonzero_off = int(np.sum(lat[1:, 1:] != 0))
    ideal_max   = 4.0   # |bias| ≤ 4 is acceptable for a 4-bit S-box

    print_row("Max off-diagonal |bias| (ideal ≤ 4)", f"{max_bias:.1f}")
    print_row("Non-zero off-diagonal entries",        str(nonzero_off))

    # ────────────────────────────────────────────────────────────
    print_section("SUMMARY")

    all_nist_ps = [
        nist_frequency_monobit(nist_bits),
        nist_block_frequency(nist_bits),
        nist_runs(nist_bits),
        nist_longest_run_of_ones(nist_bits),
        nist_binary_matrix_rank(nist_bits),
        nist_dft_spectral(nist_bits),
        nist_non_overlapping_template(nist_bits),
        nist_overlapping_template(nist_bits),
        nist_maurers_universal(nist_bits),
        nist_linear_complexity(nist_bits),
        *nist_serial(nist_bits),
        nist_approximate_entropy(nist_bits),
        *nist_cumulative_sums(nist_bits),
        *([min(re_results.values())] if re_results  else []),
        *([min(rev_results.values())] if rev_results else []),
    ]

    nist_pass = sum(1 for p in all_nist_ps if p >= ALPHA)
    nist_total = len(all_nist_ps)

    cipher_passes = [av_s, kav_s, npcr_s, uaci_s, lb_s, bb_s, ent_s].count("PASS")
    cipher_total  = 7

    print_row("NIST tests passed",   f"{nist_pass} / {nist_total}")
    print_row("Cipher tests passed", f"{cipher_passes} / {cipher_total}")

    overall = (nist_pass == nist_total) and (cipher_passes == cipher_total)
    verdict = "✓ OVERALL PASS" if overall else "✗ OVERALL FAIL"
    print()
    print(f"  {verdict}")
    print()


if __name__ == "__main__":
    run_suite()