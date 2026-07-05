"""
DNA-NATIVE CRYPTOGRAPHIC EVALUATION SUITE
Adapted specifically for DNA-GCRC cipher evaluation
Uses proper DNA base-to-bits conversion
"""

import os
import json
import time
import numpy as np
from typing import Dict, List, Tuple
from collections import Counter
from datetime import datetime

from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import text_to_dna, dna_to_text
from utils.dna_utils import dna_to_bits


class DNACryptoEvaluator:
    """DNA-specific cryptographic evaluation framework"""
    
    # DNA Base to Integer mapping (from your cipher's tests)
    BASE_TO_INT = {"A": 0, "T": 1, "C": 2, "G": 3}
    INT_TO_BASE = {v: k for k, v in BASE_TO_INT.items()}
    
    def __init__(self, output_dir="evaluation_results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # ====================================================================
    # UTILITY FUNCTIONS
    # ====================================================================
    
    @staticmethod
    def dna_to_bits(dna: str) -> List[int]:
        """Convert DNA sequence to bits (matching your cipher tests)"""
        bits = []
        for base in dna:
            v = DNACryptoEvaluator.BASE_TO_INT[base]
            bits.append((v >> 1) & 1)
            bits.append(v & 1)
        return bits
    
    @staticmethod
    def dna_to_ints(dna: str) -> List[int]:
        """Convert DNA sequence to integers"""
        return [DNACryptoEvaluator.BASE_TO_INT[base] for base in dna]
    
    @staticmethod
    def random_dna_plaintext() -> Tuple[str, str]:
        """Generate random hex plaintext and convert to DNA"""
        hex_plaintext = os.urandom(32).hex()
        dna = text_to_dna(hex_plaintext)
        return hex_plaintext, dna
    
    # ====================================================================
    # ENTROPY & RANDOMNESS TESTS
    # ====================================================================
    
    @staticmethod
    def entropy(bits: List[int]) -> float:
        """Calculate Shannon entropy"""
        p = sum(bits) / len(bits)
        if p == 0 or p == 1:
            return 0
        return -(p * np.log2(p) + (1 - p) * np.log2(1 - p))
    
    @staticmethod
    def chi_square(bits: List[int]) -> float:
        """Calculate chi-square statistic"""
        ones = sum(bits)
        zeros = len(bits) - ones
        expected = len(bits) / 2
        return ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected
    
    @staticmethod
    def serial_corr(bits: List[int]) -> float:
        """Calculate serial correlation"""
        n = len(bits)
        mean = sum(bits) / n
        num = sum((bits[i] - mean) * (bits[i + 1] - mean) for i in range(n - 1))
        den = sum((b - mean) ** 2 for b in bits)
        if den == 0:
            return 0
        return num / den
    
    # ====================================================================
    # NPCR & UACI (DNA-Specific Metrics)
    # ====================================================================
    
    @staticmethod
    def npcr_uaci(dna1: str, dna2: str) -> Tuple[float, float]:
        """
        Number of Pixel Change Rate (NPCR) and 
        Unified Average Change in Intensity (UACI)
        """
        a = DNACryptoEvaluator.dna_to_ints(dna1)
        b = DNACryptoEvaluator.dna_to_ints(dna2)
        
        n = len(a)
        changed = sum(1 for i in range(n) if a[i] != b[i])
        npcr = changed / n
        
        # UACI: average absolute difference normalized by max value
        uaci = sum(abs(a[i] - b[i]) for i in range(n)) / (3 * n)
        
        return npcr, uaci
    
    # ====================================================================
    # AVALANCHE ANALYSIS
    # ====================================================================
    
    def avalanche_analysis(self, cipher: GCRC, num_tests: int = 1000) -> Dict:
        """Test avalanche effect on DNA basis"""
        print(f"\n[*] Running avalanche analysis ({num_tests} tests)...")
        
        avalanche_values = []
        npcr_values = []
        uaci_values = []
        
        for _ in range(num_tests):
            _, dna_pt = self.random_dna_plaintext()
            
            # Encrypt original
            dna_ct1 = cipher.encrypt(dna_pt)
            
            # Flip one random DNA base
            pt_list = list(dna_pt)
            flip_idx = np.random.randint(len(pt_list))
            bases = ["A", "T", "C", "G"]
            old_base = pt_list[flip_idx]
            new_base = np.random.choice([b for b in bases if b != old_base])
            pt_list[flip_idx] = new_base
            dna_pt2 = "".join(pt_list)
            
            # Encrypt modified
            dna_ct2 = cipher.encrypt(dna_pt2)
            
            # Calculate metrics on DNA bases
            changed_bases = sum(1 for i in range(len(dna_ct1)) if dna_ct1[i] != dna_ct2[i])
            base_avalanche = (changed_bases / len(dna_ct1)) * 100
            avalanche_values.append(base_avalanche)
            
            # NPCR/UACI
            npcr, uaci = self.npcr_uaci(dna_ct1, dna_ct2)
            npcr_values.append(npcr * 100)
            uaci_values.append(uaci * 100)
        
        results = {
            "mean_avalanche": float(np.mean(avalanche_values)),
            "std_avalanche": float(np.std(avalanche_values)),
            "min_avalanche": float(np.min(avalanche_values)),
            "max_avalanche": float(np.max(avalanche_values)),
            "mean_npcr": float(np.mean(npcr_values)),
            "mean_uaci": float(np.mean(uaci_values)),
            "target_avalanche": 50.0,  # Standard crypto target: ~50% base changes (2 of 4)
            "pass": abs(np.mean(npcr_values) - 50.0) < 10.0,
        }
        
        print(f"  Mean Avalanche (bases): {results['mean_avalanche']:.2f}%")
        print(f"  Mean NPCR:              {results['mean_npcr']:.2f}%")
        print(f"  Mean UACI:              {results['mean_uaci']:.2f}%")
        print(f"  PASS:                   {results['pass']}")
        
        return results
    
    # ====================================================================
    # KEY SENSITIVITY
    # ====================================================================
    
    def key_sensitivity_analysis(self, cipher: GCRC, num_tests: int = 1000) -> Dict:
        """Test key bit sensitivity"""
        print(f"\n[*] Running key sensitivity analysis ({num_tests} tests)...")
        
        sensitivity_values = []
        
        for _ in range(num_tests):
            _, dna_pt = self.random_dna_plaintext()
            
            # Encrypt with original key
            dna_ct1 = cipher.encrypt(dna_pt)
            
            # Flip one key bit and re-encrypt
            key_bits = list(cipher.key)
            flip_idx = np.random.randint(len(key_bits))
            old_char = key_bits[flip_idx]
            # Flip character (simple modification)
            key_bits[flip_idx] = chr(ord(old_char) + 1) if ord(old_char) < 122 else chr(ord(old_char) - 1)
            
            # Create new cipher with modified key
            cipher2 = GCRC("".join(key_bits))
            dna_ct2 = cipher2.encrypt(dna_pt)
            
            # Calculate base change
            changed_bases = sum(1 for i in range(len(dna_ct1)) if dna_ct1[i] != dna_ct2[i])
            sensitivity_pct = (changed_bases / len(dna_ct1)) * 100
            sensitivity_values.append(sensitivity_pct)
        
        results = {
            "mean_sensitivity": float(np.mean(sensitivity_values)),
            "std_sensitivity": float(np.std(sensitivity_values)),
            "min_sensitivity": float(np.min(sensitivity_values)),
            "max_sensitivity": float(np.max(sensitivity_values)),
            "target_sensitivity": 75.0,
            "pass": abs(np.mean(sensitivity_values) - 75.0) < 10.0,
        }
        
        print(f"  Mean Sensitivity:  {results['mean_sensitivity']:.2f}%")
        print(f"  Std Dev:           {results['std_sensitivity']:.2f}%")
        print(f"  PASS:              {results['pass']}")
        
        return results
    
    # ====================================================================
    # DNA BASE DISTRIBUTION
    # ====================================================================
    
    def base_distribution_test(self, ciphertexts: List[str]) -> Dict:
        """Test uniform distribution of DNA bases"""
        print("\n[*] Running DNA base distribution analysis...")
        
        all_bases = "".join(ciphertexts)
        base_counts = Counter(all_bases)
        
        # Chi-square test for uniformity
        total_bases = len(all_bases)
        expected_freq = total_bases / 4  # 4 DNA bases
        
        chi_square_stat = sum(
            ((base_counts.get(b, 0) - expected_freq) ** 2) / expected_freq
            for b in ["A", "T", "C", "G"]
        )
        
        # Degrees of freedom = 3 (4 bases - 1)
        # Critical value at 0.05 significance: 7.815
        pass_uniformity = chi_square_stat < 10.0
        
        results = {
            "chi_square_statistic": float(chi_square_stat),
            "critical_value_0_05": 7.815,
            "pass_uniformity": pass_uniformity,
            "total_bases_tested": total_bases,
            "base_distribution": {b: base_counts.get(b, 0) for b in ["A", "T", "C", "G"]},
        }
        
        print(f"  Chi-Square Stat:  {chi_square_stat:.2f}")
        print(f"  Critical Value:   7.815 (α=0.05)")
        print(f"  Pass Uniformity:  {pass_uniformity}")
        for base in ["A", "T", "C", "G"]:
            count = base_counts.get(base, 0)
            pct = (count / total_bases * 100) if total_bases > 0 else 0
            print(f"    Base {base}:  {count:,} ({pct:.2f}%)")
        
        return results
    
    # ====================================================================
    # BIT-LEVEL ENTROPY
    # ====================================================================
    
    def bit_entropy_analysis(self, ciphertexts: List[str]) -> Dict:
        """Analyze bit-level entropy of DNA ciphertexts"""
        print("\n[*] Running bit-level entropy analysis...")
        
        all_bits = []
        for dna_ct in ciphertexts:
            all_bits.extend(self.dna_to_bits(dna_ct))
        
        ent = self.entropy(all_bits)
        chi_sq = self.chi_square(all_bits)
        ser_corr = self.serial_corr(all_bits)
        
        results = {
            "bit_entropy": float(ent),
            "chi_square": float(chi_sq),
            "serial_correlation": float(ser_corr),
            "target_entropy": 1.0,
            "target_chi_square": 10.0,
        }
        
        print(f"  Bit Entropy:       {ent:.6f}/1.0")
        print(f"  Chi-Square:        {chi_sq:.6f}")
        print(f"  Serial Corr:       {ser_corr:.6f}")
        
        return results
    
    # ====================================================================
    # MAIN EVALUATION
    # ====================================================================
    
    def evaluate_dna_cipher(self, cipher_name: str, cipher: GCRC, 
                           num_samples: int = 1000, num_tests: int = 500):
        """Run complete evaluation for DNA cipher"""
        
        print(f"\n{'='*70}")
        print(f"EVALUATING: {cipher_name}")
        print(f"{'='*70}")
        
        start_time = time.time()
        
        # Generate and encrypt test samples
        print(f"\n[*] Generating and encrypting {num_samples} samples...")
        ciphertexts = []
        for i in range(num_samples):
            _, dna_pt = self.random_dna_plaintext()
            dna_ct = cipher.encrypt(dna_pt)
            ciphertexts.append(dna_ct)
            if (i + 1) % 100 == 0:
                print(f"  [{i+1}/{num_samples}] encrypted")
        
        # Run all tests
        results = {
            "cipher_name": cipher_name,
            "timestamp": self.timestamp,
            "num_samples": num_samples,
            "num_tests": num_tests,
            "ciphertext_sample_length": len(ciphertexts[0]),
        }
        
        results["avalanche"] = self.avalanche_analysis(cipher, num_tests)
        results["key_sensitivity"] = self.key_sensitivity_analysis(cipher, num_tests)
        results["base_distribution"] = self.base_distribution_test(ciphertexts)
        results["bit_entropy"] = self.bit_entropy_analysis(ciphertexts)
        
        results["total_time_seconds"] = time.time() - start_time
        
        self.results[cipher_name] = results
        
        print(f"\n[+] Evaluation completed in {results['total_time_seconds']:.2f}s")
        
        return results
    
    # ====================================================================
    # REPORTING
    # ====================================================================
    
    def generate_report(self) -> str:
        """Generate comprehensive evaluation report"""
        
        report = f"""
{'='*80}
DNA-GCRC CRYPTOGRAPHIC EVALUATION REPORT
DNA-Native Cipher Analysis
{'='*80}

Timestamp: {self.timestamp}
Evaluation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'='*80}
EVALUATION METHODOLOGY
{'='*80}

This evaluation uses DNA-native metrics specifically designed for DNA-based
ciphers. Unlike traditional byte-oriented tests, we measure:

1. DNA Base Distribution: Uniform distribution of A, T, C, G bases
2. Base Avalanche Effect: When 1 DNA base flips, how many output bases change?
   - Expected: ~75% (3 out of 4 bases, since one changed)
3. Key Sensitivity: Key bit changes propagate to base changes
4. Bit-Level Entropy: Treating DNA bases as 2-bit values
5. NPCR/UACI: DNA-specific differential metrics

{'='*80}
RESULTS
{'='*80}

"""
        
        for cipher_name, results in self.results.items():
            report += f"\n{cipher_name.upper()}\n"
            report += "-" * 50 + "\n"
            report += f"Samples: {results['num_samples']}\n"
            report += f"Tests: {results['num_tests']}\n"
            report += f"Sample DNA Length: {results['ciphertext_sample_length']} bases\n"
            report += f"Time: {results['total_time_seconds']:.2f}s\n\n"
            
            # Avalanche
            report += "AVALANCHE EFFECT (DNA Bases)\n"
            aval = results['avalanche']
            report += f"  Mean Avalanche:    {aval['mean_avalanche']:.2f}% (target: 75%)\n"
            report += f"  Std Dev:           {aval['std_avalanche']:.2f}%\n"
            report += f"  NPCR:              {aval['mean_npcr']:.2f}% (DNA bases changed)\n"
            report += f"  UACI:              {aval['mean_uaci']:.2f}%\n"
            report += f"  Status:            {'PASS' if aval['pass'] else 'FAIL'}\n\n"
            
            # Key Sensitivity
            report += "KEY SENSITIVITY\n"
            ks = results['key_sensitivity']
            report += f"  Mean Sensitivity:  {ks['mean_sensitivity']:.2f}% (target: 75%)\n"
            report += f"  Status:            {'PASS' if ks['pass'] else 'FAIL'}\n\n"
            
            # Base Distribution
            report += "DNA BASE DISTRIBUTION\n"
            dist = results['base_distribution']
            report += f"  Chi-Square:        {dist['chi_square_statistic']:.2f}\n"
            report += f"  Critical (0.05):   {dist['critical_value_0_05']:.2f}\n"
            report += f"  Status:            {'PASS' if dist['pass_uniformity'] else 'FAIL'}\n"
            report += f"  Bases Tested:      {dist['total_bases_tested']:,}\n"
            for base in ["A", "T", "C", "G"]:
                count = dist['base_distribution'].get(base, 0)
                report += f"    {base}: {count:,}\n"
            report += "\n"
            
            # Bit Entropy
            report += "BIT-LEVEL ENTROPY\n"
            be = results['bit_entropy']
            report += f"  Entropy:           {be['bit_entropy']:.6f}/1.0\n"
            report += f"  Chi-Square:        {be['chi_square']:.6f}\n"
            report += f"  Serial Corr:       {be['serial_correlation']:.6f}\n\n"
        
        report += f"\n{'='*80}\n"
        report += "INTERPRETATION GUIDE\n"
        report += f"{'='*80}\n\n"
        
        report += """
AVALANCHE EFFECT (DNA Bases):
  - When 1 DNA base in plaintext changes, output should have ~75% of bases different
  - 75% means 3 out of 4 bases changed (good diffusion)
  - Target: 75% ± 10%
  - PASS if within acceptable range

NPCR (Number of base Change Rate):
  - Percentage of output bases that changed
  - Target: 75% (since we flip 1 input base)
  - >70% indicates good diffusion

UACI (Unified Average Change in Intensity):
  - Average magnitude of change across DNA bases (0-3 scale)
  - Target: High value indicating large changes

DNA Base Distribution:
  - All 4 bases (A, T, C, G) should appear ~equally often
  - Chi-square < 7.815 means uniform distribution (PASS)
  - Chi-square > 7.815 means biased distribution (FAIL)

Bit-Level Entropy:
  - Treating DNA bases as 2-bit values (A=00, T=01, C=10, G=11)
  - Should approach 1.0 (maximum entropy)
  - Chi-square on bits should be low (<10)
"""
        
        report += f"\n{'='*80}\nEND OF REPORT\n{'='*80}\n"
        
        return report
    
    def save_results(self, filename=None):
        """Save evaluation results"""
        if filename is None:
            filename = f"dna_evaluation_{self.timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n[+] Results saved to {filepath}")
        
        # Save text report
        report_filename = f"dna_evaluation_{self.timestamp}.txt"
        report_path = os.path.join(self.output_dir, report_filename)
        
        with open(report_path, 'w') as f:
            f.write(self.generate_report())
        
        print(f"[+] Report saved to {report_path}")


if __name__ == "__main__":
    print("DNA Crypto Evaluation Suite - Ready to use")
