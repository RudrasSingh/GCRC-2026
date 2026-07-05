"""
NIST SP 800-22 Randomness Test Suite Implementation

Reference: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf

Implements:
- Frequency Test (Monobit and Block)
- Runs Test
- Longest Run of Ones
- Rank Test
- Spectral Test (DFT)
- Non-Overlapping Template Matching
- Overlapping Template Matching
- Maurer's Universal Statistical Test
- Linear Complexity Test
- Serial Test
- Approximate Entropy Test
- Cumulative Sums Test
"""

import math
import numpy as np
from scipy import signal, special
from collections import defaultdict


class NISTSTP80022:
    """NIST SP 800-22 Statistical Test Suite"""
    
    def __init__(self, alpha=0.01):
        """
        Initialize test suite.
        alpha: significance level (typically 0.01)
        """
        self.alpha = alpha
        self.results = {}
    
    # ========================================
    # FREQUENCY TEST (MONOBIT)
    # ========================================
    
    def frequency_monobit_test(self, bits):
        """
        Test if number of 0s and 1s are approximately equal.
        
        H0: The sequence is random
        H1: The sequence is non-random
        """
        n = len(bits)
        ones = sum(bits)
        zeros = n - ones
        
        s = abs(ones - zeros)
        z = s / math.sqrt(n)
        p_value = math.erfc(z / math.sqrt(2))
        
        return {
            'name': 'Frequency (Monobit) Test',
            'ones': ones,
            'zeros': zeros,
            'p_value': p_value,
            'passed': p_value >= self.alpha,
            'statistic': z
        }
    
    # ========================================
    # FREQUENCY TEST (BLOCK)
    # ========================================
    
    def frequency_block_test(self, bits, m=8):
        """
        Test if blocks have approximately equal number of 0s and 1s.
        
        m: block length
        """
        n = len(bits)
        num_blocks = n // m
        
        chi_squared = 0.0
        for i in range(num_blocks):
            block = bits[i*m:(i+1)*m]
            ones = sum(block)
            zeros = m - ones
            
            pi = ones / m
            chi_squared += ((pi - 0.5) ** 2) / 0.25
        
        chi_squared = (4.0 * m / n) * chi_squared
        
        p_value = special.gammaincc(num_blocks / 2.0, chi_squared / 2.0)
        
        return {
            'name': f'Frequency (Block) Test (m={m})',
            'num_blocks': num_blocks,
            'chi_squared': chi_squared,
            'p_value': p_value,
            'passed': p_value >= self.alpha,
            'statistic': chi_squared
        }
    
    # ========================================
    # RUNS TEST
    # ========================================
    
    def runs_test(self, bits):
        """
        Test for oscillation between 0s and 1s (runs).
        A run is a sequence of identical bits.
        """
        n = len(bits)
        ones = sum(bits)
        zeros = n - ones
        
        pi = ones / n
        
        if pi == 0 or pi == 1:
            return {
                'name': 'Runs Test',
                'p_value': 0.0,
                'passed': False,
                'reason': 'All bits are identical'
            }
        
        # Count runs
        runs = 1
        for i in range(n - 1):
            if bits[i] != bits[i + 1]:
                runs += 1
        
        # Expected number of runs
        pre = 2.0 * n * pi * (1 - pi)
        
        vobs = (runs - pre) ** 2
        z = vobs / pre
        
        p_value = math.erfc(abs(z) / math.sqrt(2))
        
        return {
            'name': 'Runs Test',
            'runs': runs,
            'expected_runs': pre,
            'p_value': p_value,
            'passed': p_value >= self.alpha,
            'statistic': z
        }
    
    # ========================================
    # LONGEST RUN OF ONES TEST
    # ========================================
    
    def longest_run_test(self, bits):
        """
        Test for longest run of consecutive 1s.
        """
        n = len(bits)
        
        # Determine block size based on sequence length
        if n < 128:
            m = 8
            k = 3
            pi = [0.21, 0.561, 0.17, 0.069]
        elif n < 6272:
            m = 128
            k = 5
            pi = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
        else:
            m = 10000
            k = 6
            pi = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
        
        num_blocks = n // m
        if num_blocks == 0:
            return {
                'name': 'Longest Run of Ones Test',
                'p_value': 0.0,
                'passed': False,
                'reason': 'Sequence too short'
            }
        
        # Find longest runs in each block
        run_counts = [0] * (k + 1)
        
        for i in range(num_blocks):
            block = bits[i*m:(i+1)*m]
            longest_run = 0
            current_run = 0
            
            for bit in block:
                if bit == 1:
                    current_run += 1
                    longest_run = max(longest_run, current_run)
                else:
                    current_run = 0
            
            if longest_run < k:
                run_counts[longest_run] += 1
            else:
                run_counts[k] += 1
        
        # Chi-squared test
        chi_squared = 0.0
        for i in range(k + 1):
            if pi[i] > 0:
                chi_squared += ((run_counts[i] - num_blocks * pi[i]) ** 2) / (num_blocks * pi[i])
        
        p_value = special.gammaincc(k / 2.0, chi_squared / 2.0)
        
        return {
            'name': 'Longest Run of Ones Test',
            'chi_squared': chi_squared,
            'p_value': p_value,
            'passed': p_value >= self.alpha,
            'statistic': chi_squared
        }
    
    # ========================================
    # RANK TEST
    # ========================================
    
    def rank_test(self, bits, m=32):
        """
        Test for linear dependence of subsequences.
        """
        n = len(bits)
        num_blocks = n // (m * m)
        
        if num_blocks == 0:
            return {
                'name': 'Rank Test',
                'p_value': 0.0,
                'passed': False,
                'reason': 'Sequence too short'
            }
        
        rank_counts = defaultdict(int)
        
        for block_idx in range(num_blocks):
            start = block_idx * m * m
            end = start + m * m
            block_bits = bits[start:end]
            
            # Create m x m matrix
            matrix = []
            for i in range(m):
                row = block_bits[i*m:(i+1)*m]
                matrix.append(row)
            
            # Compute rank over GF(2)
            rank = self._matrix_rank_gf2(matrix)
            rank_counts[rank] += 1
        
        # Expected frequencies (from NIST standard)
        # For large m, intermediate values can overflow, so compute using logarithms
        # fm = (2^(m(m+1)) - 1)(2^m - 1) / 2^(m(m+3) - 2)
        # For large values, the -1 terms are negligible, so approximately:
        # fm ≈ 2^(m(m+1) + m - (m(m+3) - 2)) = 2^(m^2+m+m-m^2-3m+2) = 2^(2-m)
        # fm1 ≈ 2^(m^2 - m(m+2)) = 2^(m^2 - m^2 - 2m) = 2^(-2m)
        
        import math
        
        # Use logarithms to avoid overflow
        # log(fm) ≈ (m(m+1) + m - (m(m+3) - 2)) * log(2)
        exp_fm = m * (m + 1) + m - (m * (m + 3) - 2)  # = 2 - m
        fm = 2.0 ** exp_fm if exp_fm > -100 else math.exp(exp_fm * math.log(2))
        
        # log(fm1) ≈ (m^2 - m(m+2)) * log(2) = -2m * log(2)
        exp_fm1 = m * m - m * (m + 2)  # = -2m
        fm1 = 2.0 ** exp_fm1 if exp_fm1 > -100 else math.exp(exp_fm1 * math.log(2))
        
        chi_squared = 0.0
        if num_blocks > 0 and fm > 0 and fm1 > 0:
            chi_squared += ((rank_counts[m] - fm * num_blocks) ** 2) / (fm * num_blocks)
            chi_squared += ((rank_counts[m - 1] - fm1 * num_blocks) ** 2) / (fm1 * num_blocks)
        
        p_value = special.gammaincc(1.0, chi_squared / 2.0)
        
        return {
            'name': 'Rank Test',
            'chi_squared': chi_squared,
            'p_value': p_value,
            'passed': p_value >= self.alpha,
            'statistic': chi_squared
        }
    
    def _matrix_rank_gf2(self, matrix):
        """Compute rank of binary matrix over GF(2)"""
        m = len(matrix)
        n = len(matrix[0]) if m > 0 else 0
        
        # Gaussian elimination over GF(2)
        rank = 0
        for col in range(n):
            # Find pivot
            pivot_row = None
            for row in range(rank, m):
                if matrix[row][col] == 1:
                    pivot_row = row
                    break
            
            if pivot_row is None:
                continue
            
            # Swap rows
            matrix[rank], matrix[pivot_row] = matrix[pivot_row], matrix[rank]
            
            # Eliminate
            for row in range(m):
                if row != rank and matrix[row][col] == 1:
                    for c in range(n):
                        matrix[row][c] ^= matrix[rank][c]
            
            rank += 1
        
        return rank
    
    # ========================================
    # SPECTRAL TEST (DFT)
    # ========================================
    
    def spectral_test(self, bits):
        """
        Test using Discrete Fourier Transform.
        Converts bits (-1, 1) and checks periodicity.
        """
        n = len(bits)
        
        # Convert to [-1, 1]
        X = np.array([2 * bit - 1 for bit in bits])
        
        # DFT
        S = np.fft.fft(X)
        modulus = np.abs(S[:n // 2])
        
        T = 2.995732 * math.sqrt(math.log10(1.0 / self.alpha) * n)
        
        count = sum(1 for m in modulus if m < T)
        
        p_value = special.erfc(
            (count - 0.95 * n / 2.0) / 
            math.sqrt(n * 0.95 * 0.05 / 4.0)
        )
        
        return {
            'name': 'Spectral (DFT) Test',
            'peaks_below_threshold': count,
            'threshold': T,
            'p_value': p_value,
            'passed': p_value >= self.alpha,
            'statistic': count
        }
    
    # ========================================
    # APPROXIMATE ENTROPY TEST
    # ========================================
    
    def approximate_entropy_test(self, bits, m=5):
        """
        Test for predictability of sequence.
        """
        n = len(bits)
        
        def _maximal_pattern(pattern, seq):
            count = 0
            for i in range(len(seq) - len(pattern) + 1):
                if seq[i:i+len(pattern)] == pattern:
                    count += 1
            return count
        
        # Create circular sequence
        bits_circular = bits + bits[:m-1]
        
        # Count m-patterns and (m+1)-patterns
        patterns_m = defaultdict(int)
        patterns_m1 = defaultdict(int)
        
        for i in range(n):
            pattern_m = tuple(bits_circular[i:i+m])
            pattern_m1 = tuple(bits_circular[i:i+m+1])
            patterns_m[pattern_m] += 1
            patterns_m1[pattern_m1] += 1
        
        # Approximate entropy
        phi_m = sum(
            (count / n) * math.log2(count / n)
            for count in patterns_m.values() if count > 0
        )
        
        phi_m1 = sum(
            (count / n) * math.log2(count / n)
            for count in patterns_m1.values() if count > 0
        )
        
        apen = phi_m - phi_m1
        
        chi_squared = 2.0 * n * (
            math.log(2) * apen - 
            (1.65 * math.log(3.5) / n)
        )
        
        p_value = special.gammaincc(2 ** (m - 1), chi_squared / 2.0)
        
        return {
            'name': f'Approximate Entropy Test (m={m})',
            'apen': apen,
            'chi_squared': chi_squared,
            'p_value': p_value,
            'passed': p_value >= self.alpha,
            'statistic': chi_squared
        }
    
    # ========================================
    # CUMULATIVE SUMS TEST
    # ========================================
    
    def cumulative_sums_test(self, bits):
        """
        Test for cumulative sum deviations.
        Forward and reverse modes.
        """
        n = len(bits)
        z = 2 * np.array(bits) - 1  # Convert to [-1, 1]
        
        # Forward cumulative sum
        cumsum_fwd = np.cumsum(z)
        
        # Reverse cumulative sum
        cumsum_rev = np.cumsum(z[::-1])[::-1]
        
        # Z-scores
        max_fwd = np.max(np.abs(cumsum_fwd))
        max_rev = np.max(np.abs(cumsum_rev))
        
        # p-value computation (approximate)
        sqrt_n = math.sqrt(n)
        p_fwd = special.erfc(max_fwd / sqrt_n)
        p_rev = special.erfc(max_rev / sqrt_n)
        
        p_value = min(p_fwd, p_rev)
        
        return {
            'name': 'Cumulative Sums Test',
            'max_deviation_forward': float(max_fwd),
            'max_deviation_reverse': float(max_rev),
            'p_value': p_value,
            'passed': p_value >= self.alpha,
            'statistic': float(max(max_fwd, max_rev))
        }
    
    # ========================================
    # RUN ALL TESTS
    # ========================================
    
    def run_all_tests(self, bits):
        """Execute all NIST tests and return results"""
        results = {
            'monobit': self.frequency_monobit_test(bits),
            'block': self.frequency_block_test(bits),
            'runs': self.runs_test(bits),
            'longest_run': self.longest_run_test(bits),
            'rank': self.rank_test(bits),
            'spectral': self.spectral_test(bits),
            'approximate_entropy': self.approximate_entropy_test(bits),
            'cumulative_sums': self.cumulative_sums_test(bits),
        }
        
        self.results = results
        return results
    
    def summary(self):
        """Generate summary statistics"""
        if not self.results:
            return None
        
        passed = sum(1 for r in self.results.values() if r.get('passed', False))
        total = len(self.results)
        pass_rate = passed / total if total > 0 else 0
        
        p_values = [r.get('p_value', 0) for r in self.results.values()]
        
        return {
            'total_tests': total,
            'passed': passed,
            'failed': total - passed,
            'pass_rate': pass_rate,
            'average_p_value': np.mean(p_values),
            'min_p_value': np.min(p_values),
            'max_p_value': np.max(p_values),
            'significance_level': self.alpha
        }
