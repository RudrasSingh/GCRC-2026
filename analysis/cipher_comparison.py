"""
Comparison Benchmark Module

Provides AES and DES implementations for comparison testing.
Uses PyCryptodome for industry-standard implementations.
"""

import os
import hashlib
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import numpy as np


class AESBenchmark:
    """AES-256-CBC Implementation for Comparison"""
    
    @staticmethod
    def generate_key():
        """Generate 256-bit AES key"""
        return get_random_bytes(32)
    
    @staticmethod
    def generate_iv():
        """Generate 128-bit IV"""
        return get_random_bytes(16)
    
    @staticmethod
    def encrypt(plaintext, key, iv=None):
        """Encrypt plaintext with AES-256-CBC"""
        if iv is None:
            iv = AESBenchmark.generate_iv()
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        
        return ciphertext, iv
    
    @staticmethod
    def decrypt(ciphertext, key, iv):
        """Decrypt ciphertext with AES-256-CBC"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, AES.block_size)
        return plaintext


class DES3Benchmark:
    """Triple DES (EDE) Implementation for Comparison"""
    
    @staticmethod
    def generate_key():
        """Generate 168-bit Triple DES key (3x 56-bit)"""
        return get_random_bytes(24)
    
    @staticmethod
    def generate_iv():
        """Generate 64-bit IV"""
        return get_random_bytes(8)
    
    @staticmethod
    def encrypt(plaintext, key, iv=None):
        """Encrypt plaintext with Triple DES CBC"""
        if iv is None:
            iv = DES3Benchmark.generate_iv()
        
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded = pad(plaintext, DES3.block_size)
        ciphertext = cipher.encrypt(padded)
        
        return ciphertext, iv
    
    @staticmethod
    def decrypt(ciphertext, key, iv):
        """Decrypt ciphertext with Triple DES CBC"""
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, DES3.block_size)
        return plaintext


class CipherComparator:
    """Compare GCRC, AES, and DES across multiple metrics"""
    
    def __init__(self, gcrc_instance=None):
        self.gcrc = gcrc_instance
    
    # ========================================
    # PERFORMANCE METRICS
    # ========================================
    
    def benchmark_throughput(self, cipher_name, num_blocks=1000, block_size=64):
        """
        Measure encryption throughput (MB/s)
        
        Args:
            cipher_name: 'GCRC', 'AES', or 'DES3'
            num_blocks: number of blocks to encrypt
            block_size: bytes per block
        """
        import time
        
        plaintext = os.urandom(block_size)
        
        if cipher_name == 'AES':
            key = AESBenchmark.generate_key()
            
            start = time.time()
            for _ in range(num_blocks):
                AESBenchmark.encrypt(plaintext, key)
            elapsed = time.time() - start
            
            total_bytes = num_blocks * block_size
            
        elif cipher_name == 'DES3':
            key = DES3Benchmark.generate_key()
            
            start = time.time()
            for _ in range(num_blocks):
                DES3Benchmark.encrypt(plaintext, key)
            elapsed = time.time() - start
            
            total_bytes = num_blocks * block_size
            
        elif cipher_name == 'GCRC':
            if self.gcrc is None:
                return None
            
            key = os.urandom(32).hex()[:32]
            
            start = time.time()
            for _ in range(num_blocks):
                self.gcrc.encrypt(plaintext.hex())
            elapsed = time.time() - start
            
            total_bytes = num_blocks * block_size
        
        else:
            return None
        
        throughput_mbs = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0
        
        return {
            'cipher': cipher_name,
            'blocks': num_blocks,
            'block_size': block_size,
            'total_time_s': elapsed,
            'throughput_mbs': throughput_mbs,
            'operations_per_sec': num_blocks / elapsed if elapsed > 0 else 0
        }
    
    # ========================================
    # STATISTICAL PROPERTIES
    # ========================================
    
    def compare_output_statistics(self, num_samples=1000, sample_size=32):
        """
        Compare output statistics across ciphers
        
        Returns byte value distributions, entropy, etc.
        """
        results = {}
        
        for cipher_name in ['GCRC', 'AES', 'DES3']:
            if cipher_name == 'GCRC' and self.gcrc is None:
                continue
            
            byte_values = []
            
            for _ in range(num_samples):
                plaintext = os.urandom(sample_size)
                
                if cipher_name == 'AES':
                    key = AESBenchmark.generate_key()
                    ct, _ = AESBenchmark.encrypt(plaintext, key)
                elif cipher_name == 'DES3':
                    key = DES3Benchmark.generate_key()
                    ct, _ = DES3Benchmark.encrypt(plaintext, key)
                else:  # GCRC
                    key = os.urandom(32).hex()[:32]
                    ct_hex = self.gcrc.encrypt(plaintext.hex())
                    ct = bytes.fromhex(ct_hex) if isinstance(ct_hex, str) else ct_hex
                
                byte_values.extend(ct)
            
            byte_freq = {}
            for byte_val in byte_values:
                byte_freq[byte_val] = byte_freq.get(byte_val, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            for freq in byte_freq.values():
                if freq > 0:
                    p = freq / len(byte_values)
                    entropy -= p * np.log2(p)
            
            # Chi-square test (uniform distribution)
            expected_freq = len(byte_values) / 256
            chi_square = sum(
                (freq - expected_freq) ** 2 / expected_freq
                for freq in byte_freq.values()
            )
            
            results[cipher_name] = {
                'samples': num_samples,
                'total_bytes': len(byte_values),
                'unique_byte_values': len(byte_freq),
                'entropy': entropy,
                'chi_square': chi_square,
                'byte_distribution': byte_freq
            }
        
        return results
    
    # ========================================
    # RANDOMNESS PROPERTIES
    # ========================================
    
    def compare_avalanche_effect(self, num_tests=100, bit_flip_count=1):
        """
        Compare avalanche effect across ciphers.
        
        Measures: average bits changed when input bit flips
        """
        results = {}
        
        for cipher_name in ['GCRC', 'AES', 'DES3']:
            if cipher_name == 'GCRC' and self.gcrc is None:
                continue
            
            avalanche_scores = []
            
            for _ in range(num_tests):
                plaintext = bytearray(os.urandom(32))
                
                if cipher_name == 'AES':
                    key = AESBenchmark.generate_key()
                    ct1, iv = AESBenchmark.encrypt(bytes(plaintext), key)
                elif cipher_name == 'DES3':
                    key = DES3Benchmark.generate_key()
                    ct1, iv = DES3Benchmark.encrypt(bytes(plaintext), key)
                else:  # GCRC
                    key = os.urandom(32).hex()[:32]
                    ct1_hex = self.gcrc.encrypt(plaintext.hex())
                    ct1 = bytes.fromhex(ct1_hex) if isinstance(ct1_hex, str) else ct1_hex
                
                # Flip random bit
                byte_idx = np.random.randint(len(plaintext))
                bit_idx = np.random.randint(8)
                plaintext[byte_idx] ^= (1 << bit_idx)
                
                if cipher_name == 'AES':
                    ct2, _ = AESBenchmark.encrypt(bytes(plaintext), key, iv)
                elif cipher_name == 'DES3':
                    ct2, _ = DES3Benchmark.encrypt(bytes(plaintext), key, iv)
                else:  # GCRC
                    ct2_hex = self.gcrc.encrypt(plaintext.hex())
                    ct2 = bytes.fromhex(ct2_hex) if isinstance(ct2_hex, str) else ct2_hex
                
                # Hamming distance
                diff_bits = 0
                for b1, b2 in zip(ct1, ct2):
                    diff_bits += bin(b1 ^ b2).count('1')
                
                total_bits = len(ct1) * 8
                avalanche = diff_bits / total_bits if total_bits > 0 else 0
                
                avalanche_scores.append(avalanche)
            
            results[cipher_name] = {
                'tests': num_tests,
                'mean_avalanche': float(np.mean(avalanche_scores)),
                'std_avalanche': float(np.std(avalanche_scores)),
                'min_avalanche': float(np.min(avalanche_scores)),
                'max_avalanche': float(np.max(avalanche_scores)),
                'ideal_avalanche': 0.5  # Ideal is 50% bit flip
            }
        
        return results
    
    # ========================================
    # KEY SENSITIVITY
    # ========================================
    
    def compare_key_sensitivity(self, num_tests=100):
        """
        Compare how sensitive each cipher is to key changes.
        
        Measures: avalanche effect from single key bit flip
        """
        results = {}
        
        plaintext = os.urandom(32)
        
        for cipher_name in ['GCRC', 'AES', 'DES3']:
            if cipher_name == 'GCRC' and self.gcrc is None:
                continue
            
            sensitivity_scores = []
            
            for _ in range(num_tests):
                if cipher_name == 'AES':
                    key1 = AESBenchmark.generate_key()
                    ct1, iv = AESBenchmark.encrypt(plaintext, key1)
                    
                    # Flip 1 bit in key
                    key2 = bytearray(key1)
                    bit_idx = np.random.randint(len(key2) * 8)
                    byte_idx = bit_idx // 8
                    bit_pos = bit_idx % 8
                    key2[byte_idx] ^= (1 << bit_pos)
                    
                    ct2, _ = AESBenchmark.encrypt(plaintext, bytes(key2), iv)
                    
                elif cipher_name == 'DES3':
                    key1 = DES3Benchmark.generate_key()
                    ct1, iv = DES3Benchmark.encrypt(plaintext, key1)
                    
                    # Flip 1 bit in key
                    key2 = bytearray(key1)
                    bit_idx = np.random.randint(len(key2) * 8)
                    byte_idx = bit_idx // 8
                    bit_pos = bit_idx % 8
                    key2[byte_idx] ^= (1 << bit_pos)
                    
                    ct2, _ = DES3Benchmark.encrypt(plaintext, bytes(key2), iv)
                    
                else:  # GCRC
                    key1 = os.urandom(32).hex()[:32]
                    ct1_hex = self.gcrc.encrypt(plaintext.hex())
                    ct1 = bytes.fromhex(ct1_hex) if isinstance(ct1_hex, str) else ct1_hex
                    
                    # Flip 1 bit in key
                    key2_bytes = bytearray.fromhex(key1)
                    bit_idx = np.random.randint(len(key2_bytes) * 8)
                    byte_idx = bit_idx // 8
                    bit_pos = bit_idx % 8
                    key2_bytes[byte_idx] ^= (1 << bit_pos)
                    key2 = key2_bytes.hex()
                    
                    ct2_hex = self.gcrc.encrypt(plaintext.hex())
                    ct2 = bytes.fromhex(ct2_hex) if isinstance(ct2_hex, str) else ct2_hex
                
                # Hamming distance
                diff_bits = 0
                for b1, b2 in zip(ct1, ct2):
                    diff_bits += bin(b1 ^ b2).count('1')
                
                total_bits = len(ct1) * 8
                sensitivity = diff_bits / total_bits if total_bits > 0 else 0
                
                sensitivity_scores.append(sensitivity)
            
            results[cipher_name] = {
                'tests': num_tests,
                'mean_sensitivity': float(np.mean(sensitivity_scores)),
                'std_sensitivity': float(np.std(sensitivity_scores)),
                'min_sensitivity': float(np.min(sensitivity_scores)),
                'max_sensitivity': float(np.max(sensitivity_scores))
            }
        
        return results
