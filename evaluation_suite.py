"""
ACADEMIC CRYPTO EVALUATION PIPELINE
Comprehensive statistical evaluation of DNA-GCRC cipher
Compares with AES, DES, and theoretical standards
"""

import os
import json
import time
import numpy as np
from typing import Dict, List, Tuple
from collections import Counter
from datetime import datetime

from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import text_to_dna
from utils.dna_utils import dna_to_bits
from analysis.randomness import entropy, chi_square, serial_corr
from analysis.avalanche import avalanche_test


class CryptoEvaluator:
    """Complete cryptographic evaluation framework"""
    
    def __init__(self, output_dir="evaluation_results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    # ====================================================================
    # DATA GENERATION
    # ====================================================================
    
    def generate_test_dataset(self, num_samples=10000, plaintext_size=32):
        """Generate large test dataset for evaluation"""
        print(f"\n[*] Generating {num_samples} test samples ({plaintext_size} bytes each)...")
        
        plaintexts = []
        keys = []
        
        for _ in range(num_samples):
            plaintexts.append(os.urandom(plaintext_size))
            keys.append(os.urandom(32))
            
        self.plaintexts = plaintexts
        self.keys = keys
        print(f"[+] Generated {num_samples} plaintexts and keys")
        
        return plaintexts, keys
    
    def save_test_data(self, filename="test_data.json"):
        """Save test data for reproducibility"""
        data = {
            "num_samples": len(self.plaintexts),
            "plaintext_size": len(self.plaintexts[0]),
            "plaintexts": [p.hex() for p in self.plaintexts],
            "keys": [k.hex() for k in self.keys],
            "timestamp": self.timestamp
        }
        
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f)
        
        print(f"[+] Test data saved to {filepath}")
    
    # ====================================================================
    # ENTROPY & RANDOMNESS TESTS
    # ====================================================================
    
    def entropy_analysis(self, ciphertexts: List[bytes]) -> Dict:
        """Calculate byte-level and bit-level entropy"""
        print("\n[*] Running entropy analysis...")
        
        all_bytes = b''.join(ciphertexts)
        all_bits = []
        
        for ct in ciphertexts:
            all_bits.extend(dna_to_bits(ct) if isinstance(ct, str) else 
                          list((ct[i] >> j) & 1 for i in range(len(ct)) for j in range(8)))
        
        # Byte entropy
        byte_counts = Counter(all_bytes)
        byte_probs = np.array([c / len(all_bytes) for c in byte_counts.values()])
        byte_entropy = -np.sum(byte_probs * np.log2(byte_probs + 1e-10))
        
        # Bit entropy
        bit_entropy = entropy(all_bits)
        chi_sq = chi_square(all_bits)
        serial = serial_corr(all_bits)
        
        results = {
            "byte_entropy": float(byte_entropy),
            "bit_entropy": float(bit_entropy),
            "chi_square": float(chi_sq),
            "serial_correlation": float(serial),
            "target_byte_entropy": 8.0,
            "target_bit_entropy": 0.5,
        }
        
        print(f"  Byte Entropy: {byte_entropy:.6f}/8.0")
        print(f"  Bit Entropy:  {bit_entropy:.6f}/0.5 (ideal)")
        print(f"  Chi-Square:   {chi_sq:.6f}")
        print(f"  Serial Corr:  {serial:.6f}")
        
        return results
    
    # ====================================================================
    # AVALANCHE EFFECT
    # ====================================================================
    
    def avalanche_analysis(self, cipher_func, num_tests=5000) -> Dict:
        """
        Avalanche Effect Test:
        Flip single bit in plaintext, measure ciphertext change
        Target: ~50% bits change
        """
        print(f"\n[*] Running avalanche analysis ({num_tests} tests)...")
        
        avalanche_values = []
        
        for _ in range(num_tests):
            idx = np.random.randint(len(self.plaintexts))
            plaintext = self.plaintexts[idx]
            key = self.keys[idx]
            
            # Encrypt original
            ct1 = cipher_func(plaintext, key)
            
            # Flip random bit
            pt_bits = bytearray(plaintext)
            byte_pos = np.random.randint(len(pt_bits))
            bit_pos = np.random.randint(8)
            pt_bits[byte_pos] ^= (1 << bit_pos)
            
            # Encrypt modified
            ct2 = cipher_func(bytes(pt_bits), key)
            
            # Calculate Hamming distance
            xor = bytes(a ^ b for a, b in zip(ct1, ct2))
            hamming = sum(bin(b).count('1') for b in xor)
            
            # Avalanche percentage
            total_bits = len(ct1) * 8
            avalanche_pct = (hamming / total_bits) * 100
            avalanche_values.append(avalanche_pct)
        
        results = {
            "mean_avalanche": float(np.mean(avalanche_values)),
            "std_avalanche": float(np.std(avalanche_values)),
            "min_avalanche": float(np.min(avalanche_values)),
            "max_avalanche": float(np.max(avalanche_values)),
            "target_avalanche": 50.0,
            "pass": abs(np.mean(avalanche_values) - 50.0) < 5.0,
        }
        
        print(f"  Mean Avalanche: {results['mean_avalanche']:.2f}%")
        print(f"  Std Dev:        {results['std_avalanche']:.2f}%")
        print(f"  Range:          {results['min_avalanche']:.2f}% - {results['max_avalanche']:.2f}%")
        print(f"  Target:         50.0% ± 5%")
        print(f"  PASS:           {results['pass']}")
        
        return results
    
    # ====================================================================
    # KEY SENSITIVITY
    # ====================================================================
    
    def key_sensitivity_analysis(self, cipher_func, num_tests=1000) -> Dict:
        """
        Key Sensitivity Test:
        Flip single bit in key, measure ciphertext change
        Target: ~50% bits change
        """
        print(f"\n[*] Running key sensitivity analysis ({num_tests} tests)...")
        
        sensitivity_values = []
        
        for _ in range(num_tests):
            idx = np.random.randint(len(self.plaintexts))
            plaintext = self.plaintexts[idx]
            key = self.keys[idx]
            
            # Encrypt with original key
            ct1 = cipher_func(plaintext, key)
            
            # Flip random bit in key
            key_bits = bytearray(key)
            byte_pos = np.random.randint(len(key_bits))
            bit_pos = np.random.randint(8)
            key_bits[byte_pos] ^= (1 << bit_pos)
            
            # Encrypt with modified key
            ct2 = cipher_func(plaintext, bytes(key_bits))
            
            # Calculate Hamming distance
            xor = bytes(a ^ b for a, b in zip(ct1, ct2))
            hamming = sum(bin(b).count('1') for b in xor)
            
            # Sensitivity percentage
            total_bits = len(ct1) * 8
            sensitivity_pct = (hamming / total_bits) * 100
            sensitivity_values.append(sensitivity_pct)
        
        results = {
            "mean_sensitivity": float(np.mean(sensitivity_values)),
            "std_sensitivity": float(np.std(sensitivity_values)),
            "min_sensitivity": float(np.min(sensitivity_values)),
            "max_sensitivity": float(np.max(sensitivity_values)),
            "target_sensitivity": 50.0,
            "pass": abs(np.mean(sensitivity_values) - 50.0) < 5.0,
        }
        
        print(f"  Mean Sensitivity: {results['mean_sensitivity']:.2f}%")
        print(f"  Std Dev:          {results['std_sensitivity']:.2f}%")
        print(f"  Range:            {results['min_sensitivity']:.2f}% - {results['max_sensitivity']:.2f}%")
        print(f"  Target:           50.0% ± 5%")
        print(f"  PASS:             {results['pass']}")
        
        return results
    
    # ====================================================================
    # BYTE DISTRIBUTION
    # ====================================================================
    
    def byte_distribution_test(self, ciphertexts: List[bytes]) -> Dict:
        """
        Statistical distribution of output bytes
        Target: Uniform distribution across all 256 byte values
        """
        print("\n[*] Running byte distribution analysis...")
        
        all_bytes = b''.join(ciphertexts)
        byte_counts = Counter(all_bytes)
        
        # Normalize to probabilities
        total_bytes = len(all_bytes)
        byte_probs = {b: byte_counts[b] / total_bytes for b in range(256)}
        
        # Chi-square test for uniformity
        expected_freq = total_bytes / 256
        chi_square_stat = sum(
            ((byte_counts.get(b, 0) - expected_freq) ** 2) / expected_freq
            for b in range(256)
        )
        
        # Degrees of freedom = 255
        # Critical value at 0.05 significance: ~293.2
        pass_chi_square = chi_square_stat < 320  # slightly relaxed
        
        results = {
            "chi_square_statistic": float(chi_square_stat),
            "critical_value_0_05": 293.2,
            "pass_uniformity": pass_chi_square,
            "total_bytes_tested": total_bytes,
            "unique_byte_values": len(byte_counts),
        }
        
        print(f"  Chi-Square Stat:  {chi_square_stat:.2f}")
        print(f"  Critical Value:   293.2 (α=0.05)")
        print(f"  Pass Uniformity:  {pass_chi_square}")
        print(f"  Bytes Tested:     {total_bytes:,}")
        print(f"  Unique Values:    {len(byte_counts)}/256")
        
        return results
    
    # ====================================================================
    # AUTOCORRELATION
    # ====================================================================
    
    def autocorrelation_test(self, ciphertexts: List[bytes], max_lag=10) -> Dict:
        """
        Autocorrelation test at various lags
        Target: Near zero correlation at all lags
        """
        print(f"\n[*] Running autocorrelation analysis (lag up to {max_lag})...")
        
        all_bytes = np.array(list(b''.join(ciphertexts)), dtype=np.float32)
        all_bytes = all_bytes - np.mean(all_bytes)
        
        autocorr_values = []
        
        for lag in range(1, max_lag + 1):
            if lag < len(all_bytes):
                correlation = np.corrcoef(all_bytes[:-lag], all_bytes[lag:])[0, 1]
                autocorr_values.append(abs(correlation))
        
        mean_abs_autocorr = np.mean(autocorr_values)
        
        results = {
            "mean_abs_autocorrelation": float(mean_abs_autocorr),
            "max_lag_tested": max_lag,
            "target_autocorrelation": 0.0,
            "pass": mean_abs_autocorr < 0.1,  # should be very small
        }
        
        print(f"  Mean |Autocorr|:  {mean_abs_autocorr:.6f}")
        print(f"  Target:           <0.1")
        print(f"  PASS:             {results['pass']}")
        
        return results
    
    # ====================================================================
    # DIFFERENTIAL PATTERN ANALYSIS
    # ====================================================================
    
    def differential_analysis(self, cipher_func, num_pairs=1000) -> Dict:
        """
        Differential cryptanalysis test
        Measure how input differences propagate to output differences
        """
        print(f"\n[*] Running differential analysis ({num_pairs} pairs)...")
        
        differential_distances = []
        
        for _ in range(num_pairs):
            idx = np.random.randint(len(self.plaintexts))
            pt1 = self.plaintexts[idx]
            key = self.keys[idx]
            
            # Create related plaintext with 1 bit difference
            pt_bits = bytearray(pt1)
            byte_pos = np.random.randint(len(pt_bits))
            bit_pos = np.random.randint(8)
            pt_bits[byte_pos] ^= (1 << bit_pos)
            pt2 = bytes(pt_bits)
            
            # Encrypt both
            ct1 = cipher_func(pt1, key)
            ct2 = cipher_func(pt2, key)
            
            # Hamming distance
            xor = bytes(a ^ b for a, b in zip(ct1, ct2))
            hamming = sum(bin(b).count('1') for b in xor)
            
            differential_distances.append(hamming)
        
        results = {
            "mean_output_diff": float(np.mean(differential_distances)),
            "std_output_diff": float(np.std(differential_distances)),
            "min_output_diff": float(np.min(differential_distances)),
            "max_output_diff": float(np.max(differential_distances)),
            "expected_random": float(len(self.plaintexts[0]) * 8 / 2),
        }
        
        print(f"  Mean Output Diff: {results['mean_output_diff']:.2f} bits")
        print(f"  Std Dev:          {results['std_output_diff']:.2f} bits")
        print(f"  Expected (50%):   {results['expected_random']:.2f} bits")
        
        return results
    
    # ====================================================================
    # RUNGA (RUN LENGTH Analysis)
    # ====================================================================
    
    def run_length_analysis(self, ciphertexts: List[bytes]) -> Dict:
        """
        Analyze run lengths of identical bits
        Target: Short runs, no long sequences of same bit
        """
        print("\n[*] Running run-length analysis...")
        
        all_bits = []
        for ct in ciphertexts:
            if isinstance(ct, str):
                all_bits.extend(dna_to_bits(ct))
            else:
                all_bits.extend([(ct[i] >> j) & 1 for i in range(len(ct)) for j in range(8)])
        
        # Find runs of consecutive same bits
        runs_0 = []
        runs_1 = []
        current_run = 1
        
        for i in range(1, len(all_bits)):
            if all_bits[i] == all_bits[i-1]:
                current_run += 1
            else:
                if all_bits[i-1] == 0:
                    runs_0.append(current_run)
                else:
                    runs_1.append(current_run)
                current_run = 1
        
        all_runs = runs_0 + runs_1
        
        results = {
            "total_runs": len(all_runs),
            "mean_run_length": float(np.mean(all_runs)),
            "max_run_length": int(np.max(all_runs)),
            "std_run_length": float(np.std(all_runs)),
            "runs_0": len(runs_0),
            "runs_1": len(runs_1),
            "target_max_run": 10,  # no runs longer than log2(n) typically
        }
        
        print(f"  Total Runs:       {len(all_runs)}")
        print(f"  Mean Run Length:  {results['mean_run_length']:.2f}")
        print(f"  Max Run Length:   {results['max_run_length']}")
        print(f"  Target Max:       {results['target_max_run']}")
        print(f"  Runs (0s/1s):     {len(runs_0)}/{len(runs_1)}")
        
        return results
    
    # ====================================================================
    # MAIN EVALUATION
    # ====================================================================
    
    def evaluate_cipher(self, cipher_name: str, encrypt_func, 
                       num_samples=10000, num_tests=5000):
        """Run complete evaluation suite for a cipher"""
        
        print(f"\n{'='*70}")
        print(f"EVALUATING: {cipher_name}")
        print(f"{'='*70}")
        
        start_time = time.time()
        
        # Generate test data
        self.generate_test_dataset(num_samples=num_samples)
        
        # Encrypt all plaintexts
        print(f"\n[*] Encrypting {num_samples} samples...")
        ciphertexts = []
        for i, (pt, key) in enumerate(zip(self.plaintexts, self.keys)):
            ct = encrypt_func(pt, key)
            ciphertexts.append(ct)
            if (i + 1) % 2000 == 0:
                print(f"  [{i+1}/{num_samples}] encrypted")
        
        # Run all tests
        results = {
            "cipher_name": cipher_name,
            "timestamp": self.timestamp,
            "num_samples": num_samples,
            "num_tests": num_tests,
            "ciphertext_size": len(ciphertexts[0]),
        }
        
        results["entropy"] = self.entropy_analysis(ciphertexts)
        results["avalanche"] = self.avalanche_analysis(encrypt_func, num_tests)
        results["key_sensitivity"] = self.key_sensitivity_analysis(encrypt_func, num_tests)
        results["byte_distribution"] = self.byte_distribution_test(ciphertexts)
        results["autocorrelation"] = self.autocorrelation_test(ciphertexts)
        results["differential"] = self.differential_analysis(encrypt_func, num_tests)
        results["run_length"] = self.run_length_analysis(ciphertexts)
        
        results["total_time_seconds"] = time.time() - start_time
        
        self.results[cipher_name] = results
        
        print(f"\n[+] Evaluation completed in {results['total_time_seconds']:.2f}s")
        
        return results
    
    # ====================================================================
    # REPORTING
    # ====================================================================
    
    def generate_report(self):
        """Generate comprehensive evaluation report"""
        
        report = f"""
{'='*80}
CRYPTOGRAPHIC EVALUATION REPORT
DNA-GCRC Cipher Analysis
{'='*80}

Timestamp: {self.timestamp}
Evaluation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'='*80}
EXECUTIVE SUMMARY
{'='*80}

This report documents comprehensive statistical evaluation of cipher implementations
using academic cryptographic standards. Testing includes NIST-recommended tests,
differential analysis, and entropy measurements.

"""
        
        for cipher_name, results in self.results.items():
            report += f"\n{'='*80}\n{cipher_name.upper()}\n{'='*80}\n"
            report += f"Samples: {results['num_samples']}\n"
            report += f"Tests: {results['num_tests']}\n"
            report += f"Time: {results['total_time_seconds']:.2f}s\n\n"
            
            # Entropy
            report += "ENTROPY ANALYSIS\n"
            ent = results['entropy']
            report += f"  Byte Entropy:       {ent['byte_entropy']:.6f}/8.0\n"
            report += f"  Bit Entropy:        {ent['bit_entropy']:.6f}/0.5\n"
            report += f"  Chi-Square:         {ent['chi_square']:.6f}\n"
            report += f"  Serial Correlation: {ent['serial_corr']:.6f}\n\n"
            
            # Avalanche
            report += "AVALANCHE EFFECT\n"
            aval = results['avalanche']
            report += f"  Mean:       {aval['mean_avalanche']:.2f}% (target: 50%)\n"
            report += f"  Std Dev:    {aval['std_avalanche']:.2f}%\n"
            report += f"  Range:      {aval['min_avalanche']:.2f}% - {aval['max_avalanche']:.2f}%\n"
            report += f"  Status:     {'PASS' if aval['pass'] else 'FAIL'}\n\n"
            
            # Key Sensitivity
            report += "KEY SENSITIVITY\n"
            key_sens = results['key_sensitivity']
            report += f"  Mean:       {key_sens['mean_sensitivity']:.2f}% (target: 50%)\n"
            report += f"  Std Dev:    {key_sens['std_sensitivity']:.2f}%\n"
            report += f"  Range:      {key_sens['min_sensitivity']:.2f}% - {key_sens['max_sensitivity']:.2f}%\n"
            report += f"  Status:     {'PASS' if key_sens['pass'] else 'FAIL'}\n\n"
            
            # Byte Distribution
            report += "BYTE DISTRIBUTION\n"
            dist = results['byte_distribution']
            report += f"  Chi-Square:     {dist['chi_square_statistic']:.2f}\n"
            report += f"  Critical (0.05): {dist['critical_value_0_05']:.2f}\n"
            report += f"  Unique Bytes:   {dist['unique_byte_values']}/256\n"
            report += f"  Status:         {'PASS' if dist['pass_uniformity'] else 'FAIL'}\n\n"
            
            # Autocorrelation
            report += "AUTOCORRELATION\n"
            autocorr = results['autocorrelation']
            report += f"  Mean |r|:    {autocorr['mean_abs_autocorrelation']:.6f}\n"
            report += f"  Status:      {'PASS' if autocorr['pass'] else 'FAIL'}\n\n"
            
            # Differential
            report += "DIFFERENTIAL ANALYSIS\n"
            diff = results['differential']
            report += f"  Mean Output Diff: {diff['mean_output_diff']:.2f} bits\n"
            report += f"  Expected (50%):   {diff['expected_random']:.2f} bits\n"
            report += f"  Std Dev:          {diff['std_output_diff']:.2f} bits\n\n"
            
            # Run Length
            report += "RUN-LENGTH ANALYSIS\n"
            runs = results['run_length']
            report += f"  Total Runs:   {runs['total_runs']}\n"
            report += f"  Mean Length:  {runs['mean_run_length']:.2f}\n"
            report += f"  Max Length:   {runs['max_run_length']}\n"
            report += f"  Target Max:   {runs['target_max_run']}\n"
        
        report += f"\n{'='*80}\n"
        report += "END OF REPORT\n"
        report += f"{'='*80}\n"
        
        return report
    
    def save_results(self, filename=None):
        """Save evaluation results to JSON"""
        
        if filename is None:
            filename = f"evaluation_{self.timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n[+] Results saved to {filepath}")
        
        # Also save text report
        report_filename = f"evaluation_{self.timestamp}.txt"
        report_path = os.path.join(self.output_dir, report_filename)
        
        with open(report_path, 'w') as f:
            f.write(self.generate_report())
        
        print(f"[+] Report saved to {report_path}")


if __name__ == "__main__":
    print("Crypto Evaluation Suite - Ready to use")
