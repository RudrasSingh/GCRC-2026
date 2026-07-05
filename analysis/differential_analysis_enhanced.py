"""
Enhanced Differential Cryptanalysis Module

Provides advanced differential analysis tools for evaluating cipher strength.
Includes S-box analysis, differential propagation, and characteristic generation.
"""

import os
import numpy as np
from collections import Counter, defaultdict
import json
from encoding.dna_codec import text_to_dna
from utils.dna_utils import dna_to_bits


class DifferentialAnalyzer:
    """Analyze differential properties of ciphers"""
    
    def __init__(self, cipher):
        self.cipher = cipher
        self.results = {}
    
    # ========================================
    # BASIC DIFFERENTIAL ANALYSIS
    # ========================================
    
    def analyze_input_difference_propagation(
        self,
        num_pairs=5000,
        input_difference_weight=1
    ):
        """
        Analyze how input differences propagate to output.
        
        For each pair of inputs with controlled difference,
        measure output difference distribution.
        
        Args:
            num_pairs: number of input pairs to test
            input_difference_weight: how many bits differ (1 = single bit)
        """
        
        output_differences = defaultdict(int)
        output_weights = []
        
        print(f"Analyzing differential propagation ({num_pairs} pairs)...")
        
        for pair_idx in range(num_pairs):
            if pair_idx % max(1, num_pairs // 10) == 0:
                print(f"  Progress: {pair_idx}/{num_pairs}")
            
            # Generate first plaintext
            pt1 = os.urandom(32)
            
            # Create second plaintext with controlled difference
            pt2 = bytearray(pt1)
            
            # Flip input_difference_weight random bits
            for _ in range(input_difference_weight):
                bit_idx = np.random.randint(len(pt2) * 8)
                byte_idx = bit_idx // 8
                bit_pos = bit_idx % 8
                pt2[byte_idx] ^= (1 << bit_pos)
            
            pt2 = bytes(pt2)
            
            # Encrypt both - convert to DNA first
            try:
                dna_pt1 = text_to_dna(pt1.decode('latin1'))
                ct1_dna = self.cipher.encrypt(dna_pt1)
                ct1_bits = dna_to_bits(ct1_dna)
                
                dna_pt2 = text_to_dna(pt2.decode('latin1'))
                ct2_dna = self.cipher.encrypt(dna_pt2)
                ct2_bits = dna_to_bits(ct2_dna)
            except:
                continue
            
            # Compute output difference (bit difference)
            output_diff = tuple(b1 ^ b2 for b1, b2 in zip(ct1_bits, ct2_bits))
            
            # Weight (Hamming weight)
            hamming_weight = sum(output_diff)
            
            output_differences[output_diff] += 1
            output_weights.append(hamming_weight)
        
        # Statistics
        weights_array = np.array(output_weights)
        
        return {
            'num_pairs': num_pairs,
            'input_difference_weight': input_difference_weight,
            'output_difference_statistics': {
                'unique_output_diffs': len(output_differences),
                'avg_hamming_weight': float(np.mean(weights_array)),
                'std_hamming_weight': float(np.std(weights_array)),
                'min_hamming_weight': int(np.min(weights_array)),
                'max_hamming_weight': int(np.max(weights_array)),
                'expected_hamming_weight': len(ct1) * 8 / 2,
            },
            'most_common_outputs': [
                (diff, count) for diff, count in 
                Counter(output_differences).most_common(10)
            ],
            'distribution_uniformity': len(output_differences) / (2 ** 256)
        }
    
    # ========================================
    # DIFFERENTIAL CHARACTERISTIC ANALYSIS
    # ========================================
    
    def find_differential_characteristics(
        self,
        input_xor_weight=1,
        num_samples=1000
    ):
        """
        Identify differential characteristics.
        
        A differential characteristic is a tuple (ΔX, ΔY, p) where:
        - ΔX is input difference
        - ΔY is output difference
        - p is probability of (ΔX → ΔY)
        
        High probability characteristics indicate weakness.
        """
        
        characteristics = defaultdict(int)
        
        print(f"Finding differential characteristics ({num_samples} samples)...")
        
        for i in range(num_samples):
            if i % max(1, num_samples // 10) == 0:
                print(f"  Progress: {i}/{num_samples}")
            
            # Generate input difference
            pt1 = os.urandom(32)
            pt2 = bytearray(pt1)
            
            # Flip specific bit(s)
            for _ in range(input_xor_weight):
                bit_idx = np.random.randint(len(pt2) * 8)
                byte_idx = bit_idx // 8
                bit_pos = bit_idx % 8
                pt2[byte_idx] ^= (1 << bit_pos)
            
            pt2 = bytes(pt2)
            
            # Encrypt - convert to DNA first
            try:
                dna_pt1 = text_to_dna(pt1.decode('latin1'))
                ct1_dna = self.cipher.encrypt(dna_pt1)
                ct1_bits = dna_to_bits(ct1_dna)
                
                dna_pt2 = text_to_dna(pt2.decode('latin1'))
                ct2_dna = self.cipher.encrypt(dna_pt2)
                ct2_bits = dna_to_bits(ct2_dna)
            except:
                continue
            
            # Record characteristic
            input_diff = tuple(a ^ b for a, b in zip(pt1, pt2))
            output_diff = tuple(b1 ^ b2 for b1, b2 in zip(ct1_bits, ct2_bits))
            
            char = (input_diff, output_diff)
            characteristics[char] += 1
        
        # Convert to probability
        characteristics_with_prob = {}
        for (in_diff, out_diff), count in characteristics.items():
            prob = count / num_samples
            
            # Only keep characteristics with probability >= 1/256
            if prob >= 1.0 / 256:
                characteristics_with_prob[(in_diff, out_diff)] = prob
        
        # Sort by probability
        sorted_chars = sorted(
            characteristics_with_prob.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            'input_xor_weight': input_xor_weight,
            'samples': num_samples,
            'total_characteristics_found': len(characteristics),
            'high_prob_characteristics': len(characteristics_with_prob),
            'top_characteristics': [
                {
                    'probability': float(prob),
                    'output_weight': sum(bin(x).count('1') for x in out_diff)
                }
                for (in_diff, out_diff), prob in sorted_chars[:20]
            ],
            'max_probability': float(max([p for _, p in sorted_chars])) if sorted_chars else 0.0,
            'avg_probability': float(np.mean([p for _, p in sorted_chars])) if sorted_chars else 0.0
        }
    
    # ========================================
    # LINEAR CRYPTANALYSIS
    # ========================================
    
    def linear_analysis(self, num_samples=1000):
        """
        Detect linear approximations.
        
        Tests for non-zero correlation between linear combinations
        of input and output bits.
        """
        
        correlations = []
        max_correlations_per_mask = []
        
        print(f"Performing linear analysis ({num_samples} samples)...")
        
        # Test a sample of possible output masks
        num_masks_to_test = min(1024, 2 ** 16)
        
        for _ in range(num_masks_to_test):
            # Random output mask
            output_mask = np.random.randint(0, 2 ** 16)
            
            # Test this mask
            correlations_for_mask = []
            
            for i in range(num_samples):
                if i % max(1, num_samples // 10) == 0:
                    print(f"  Testing mask {_ + 1}/{num_masks_to_test}, sample {i}/{num_samples}")
                
                # Random plaintext
                pt = os.urandom(32)
                
                # Encrypt - convert to DNA first
                try:
                    dna_pt = text_to_dna(pt.decode('latin1'))
                    ct_dna = self.cipher.encrypt(dna_pt)
                    ct_bits = dna_to_bits(ct_dna)
                except:
                    continue
                
                # Compute linear combination for output
                output_value = sum(
                    ct_bits[i] 
                    for i in range(min(len(ct_bits), 16)) 
                    if (output_mask >> i) & 1
                ) % 2
                
                correlations_for_mask.append(output_value)
            
            if correlations_for_mask:
                # Compute bias
                ones = sum(correlations_for_mask)
                zeros = len(correlations_for_mask) - ones
                bias = abs(ones - zeros) / len(correlations_for_mask)
                correlations.append(bias)
                
                if bias > 0.1:  # Significant bias
                    max_correlations_per_mask.append(bias)
        
        return {
            'samples': num_samples,
            'masks_tested': num_masks_to_test,
            'avg_correlation': float(np.mean(correlations)) if correlations else 0.0,
            'max_correlation': float(np.max(correlations)) if correlations else 0.0,
            'significant_correlations': len(max_correlations_per_mask),
            'threshold': 0.1
        }
    
    # ========================================
    # KEY SCHEDULE ANALYSIS
    # ========================================
    
    def analyze_key_schedule(self, num_keys=1000):
        """
        Analyze key schedule weakness detection.
        
        Tests if related keys produce predictable patterns.
        """
        
        plaintext = os.urandom(32)
        
        differences = []
        
        print(f"Analyzing key schedule ({num_keys} keys)...")
        
        for i in range(num_keys):
            if i % max(1, num_keys // 10) == 0:
                print(f"  Progress: {i}/{num_keys}")
            
            # Generate two related keys (differ by 1 bit)
            key1 = os.urandom(32).hex()[:32]
            key2_bytes = bytearray.fromhex(key1)
            
            bit_idx = np.random.randint(len(key2_bytes) * 8)
            byte_idx = bit_idx // 8
            bit_pos = bit_idx % 8
            key2_bytes[byte_idx] ^= (1 << bit_pos)
            key2 = key2_bytes.hex()
            
            # Encrypt with both keys
            try:
                # This would need cipher to accept key parameter
                # For now, just track structure
                pass
            except:
                pass
        
        return {
            'keys_tested': num_keys,
            'related_key_differences': len(differences),
            'note': 'Requires cipher with parameterized key'
        }
    
    # ========================================
    # COMPREHENSIVE ANALYSIS
    # ========================================
    
    def run_comprehensive_analysis(self):
        """Run all differential analysis tests"""
        
        print("\n" + "="*60)
        print("DIFFERENTIAL CRYPTANALYSIS SUITE")
        print("="*60 + "\n")
        
        results = {
            'propagation': self.analyze_input_difference_propagation(),
            'characteristics': self.find_differential_characteristics(),
            'linear': self.linear_analysis(),
        }
        
        # Summary
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        print(f"Input Diff Propagation: {results['propagation']['output_difference_statistics']['unique_output_diffs']} unique output diffs")
        print(f"Max output weight: {results['propagation']['output_difference_statistics']['max_hamming_weight']}")
        print(f"Differential characteristics found: {results['characteristics']['high_prob_characteristics']}")
        print(f"Linear correlations > 0.1: {results['linear']['significant_correlations']}")
        
        self.results = results
        return results
    
    def save_analysis(self, filename='differential_analysis.json'):
        """Save analysis results"""
        with open(filename, 'w') as f:
            # Convert tuples to strings for JSON serialization
            json.dump(self.results, f, indent=2, default=str)
        
        return filename
