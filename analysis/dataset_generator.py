"""
Dataset Generation Pipeline

Generates large, statistically rigorous datasets for cryptographic testing.
Produces binary output files suitable for NIST STS, PractRand, Dieharder.
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
import numpy as np
from encoding.dna_codec import text_to_dna
from utils.dna_utils import dna_to_bits


class DatasetGenerator:
    """Generate ciphertext datasets for external cryptanalysis"""
    
    def __init__(self, cipher, key_generator=None, output_dir='datasets'):
        """
        Args:
            cipher: GCRC or comparison cipher instance
            key_generator: function that generates keys
            output_dir: where to save binary files
        """
        self.cipher = cipher
        self.key_generator = key_generator or (lambda: os.urandom(32).hex()[:32])
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.metadata = {
            'cipher': cipher.__class__.__name__ if hasattr(cipher, '__class__') else 'Unknown',
            'created': datetime.now().isoformat(),
            'samples': 0,
            'file_size_bytes': 0,
            'plaintexts': [],
            'keys': []
        }
    
    # ========================================
    # RANDOM PLAINTEXT GENERATION
    # ========================================
    
    def generate_random_plaintexts(self, num_samples=10000, plaintext_size=64):
        """
        Generate random plaintexts for testing.
        
        Args:
            num_samples: number of plaintexts to generate
            plaintext_size: bytes per plaintext
        
        Returns:
            list of plaintext bytes
        """
        plaintexts = []
        for _ in range(num_samples):
            pt = os.urandom(plaintext_size)
            plaintexts.append(pt)
        
        return plaintexts
    
    def generate_structured_plaintexts(self, num_samples=1000, plaintext_size=64):
        """
        Generate structured plaintexts that test specific properties.
        
        Types:
        - All zeros
        - All ones
        - Alternating bits
        - Single-bit changes
        - Structured patterns
        """
        plaintexts = []
        
        # All zeros
        plaintexts.append(b'\x00' * plaintext_size)
        
        # All ones
        plaintexts.append(b'\xff' * plaintext_size)
        
        # Alternating bits
        alt1 = (b'\xaa' * plaintext_size)
        alt2 = (b'\x55' * plaintext_size)
        plaintexts.extend([alt1, alt2])
        
        # Single bit set positions
        for bit_pos in range(min(256, plaintext_size * 8)):
            pt = bytearray(plaintext_size)
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            pt[byte_idx] |= (1 << bit_idx)
            plaintexts.append(bytes(pt))
        
        # Random plaintexts for remainder
        remaining = num_samples - len(plaintexts)
        plaintexts.extend(self.generate_random_plaintexts(remaining, plaintext_size))
        
        return plaintexts[:num_samples]
    
    # ========================================
    # KEY GENERATION
    # ========================================
    
    def generate_keys(self, num_keys=100):
        """Generate random keys for testing"""
        keys = []
        for _ in range(num_keys):
            key = self.key_generator()
            keys.append(key)
        return keys
    
    # ========================================
    # DATASET CREATION
    # ========================================
    
    def create_ciphertext_stream(
        self,
        num_samples=10000,
        plaintext_size=64,
        output_filename=None,
        use_random_keys=False,
        structured=False
    ):
        """
        Create a binary stream of ciphertexts for statistical testing.
        
        This generates a file suitable for:
        - NIST STS
        - PractRand
        - Dieharder
        - entropy estimation
        
        Args:
            num_samples: number of ciphertexts to generate
            plaintext_size: bytes per plaintext
            output_filename: output file path
            use_random_keys: if True, use different key for each sample
            structured: if True, use structured plaintexts
        
        Returns:
            dict with file info and metadata
        """
        
        if output_filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f'{self.cipher.__class__.__name__ if hasattr(self.cipher, "__class__") else "cipher"}_stream_{timestamp}.bin'
        
        output_path = self.output_dir / output_filename
        
        print(f"Generating {num_samples} ciphertexts to {output_path}...")
        
        # Generate plaintexts
        if structured:
            print("  Using structured plaintexts...")
            plaintexts = self.generate_structured_plaintexts(num_samples, plaintext_size)
        else:
            print("  Using random plaintexts...")
            plaintexts = self.generate_random_plaintexts(num_samples, plaintext_size)
        
        # Generate keys
        if use_random_keys:
            print(f"  Generating {num_samples} random keys...")
            keys = self.generate_keys(num_samples)
        else:
            print("  Using single key for all samples...")
            keys = [self.key_generator()] * num_samples
        
        # Encrypt and write
        total_bytes = 0
        with open(output_path, 'wb') as f:
            for i, (pt, key) in enumerate(zip(plaintexts, keys)):
                if i % max(1, num_samples // 10) == 0:
                    print(f"  Progress: {i}/{num_samples}")
                
                # Handle different cipher interfaces
                if hasattr(self.cipher, 'encrypt'):
                    # GCRC-style - convert to DNA first
                    try:
                        # Convert plaintext to DNA
                        dna_pt = text_to_dna(pt.decode('latin1'))
                        ct_dna = self.cipher.encrypt(dna_pt)
                        ct_bits = dna_to_bits(ct_dna)
                        # Convert bit list to bytes
                        ct_bytes = bytes([
                            int(''.join(map(str, ct_bits[i:i+8])), 2)
                            for i in range(0, len(ct_bits), 8)
                        ])
                    except:
                        try:
                            # Try with key parameter
                            from cipher.gcrc_cipher import GCRC
                            from encoding.dna_codec import text_to_dna
                            from utils.dna_utils import dna_to_bits
                            
                            cipher_instance = GCRC(key) if isinstance(key, str) else GCRC(key.hex()[:32])
                            dna_pt = text_to_dna(pt.decode('latin1'))
                            ct_dna = cipher_instance.encrypt(dna_pt)
                            ct_bits = dna_to_bits(ct_dna)
                            # Convert bit list to bytes
                            ct_bytes = bytes([
                                int(''.join(map(str, ct_bits[i:i+8])), 2)
                                for i in range(0, len(ct_bits), 8)
                            ])
                        except:
                            # Fallback
                            ct_bytes = pt
                else:
                    ct_bytes = pt
                
                f.write(ct_bytes)
                total_bytes += len(ct_bytes)
        
        print(f"  Completed: {total_bytes} bytes written")
        
        # Store metadata
        self.metadata['samples'] = num_samples
        self.metadata['file_size_bytes'] = total_bytes
        self.metadata['plaintexts'] = {
            'count': num_samples,
            'size_bytes': plaintext_size,
            'type': 'structured' if structured else 'random'
        }
        self.metadata['keys'] = {
            'count': len(keys),
            'type': 'random_per_sample' if use_random_keys else 'single_key'
        }
        
        return {
            'output_file': str(output_path),
            'file_size_bytes': total_bytes,
            'num_samples': num_samples,
            'plaintext_size': plaintext_size,
            'total_ciphertext_bytes': total_bytes,
            'metadata': self.metadata
        }
    
    # ========================================
    # METADATA MANAGEMENT
    # ========================================
    
    def save_metadata(self, filename=None):
        """Save dataset metadata to JSON"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'{self.cipher.__class__.__name__ if hasattr(self.cipher, "__class__") else "cipher"}_metadata_{timestamp}.json'
        
        output_path = self.output_dir / filename
        
        with open(output_path, 'w') as f:
            json.dump(self.metadata, f, indent=2)
        
        return str(output_path)
    
    # ========================================
    # STATIC HELPER METHODS
    # ========================================
    
    @staticmethod
    def create_nist_sts_input(binary_file, num_bits=1000000):
        """
        Create NIST STS-compatible input file.
        
        NIST STS expects:
        - Binary file with contiguous bits
        - At least 1,000,000 bits recommended
        - Bit format: consecutive bits in byte order
        """
        if not os.path.exists(binary_file):
            raise FileNotFoundError(f"Binary file not found: {binary_file}")
        
        file_size = os.path.getsize(binary_file)
        available_bits = file_size * 8
        
        return {
            'file': binary_file,
            'file_size_bytes': file_size,
            'available_bits': available_bits,
            'sufficient_for_nist': available_bits >= 1000000,
            'recommended_bits': 1000000,
            'tests_possible': [
                'Frequency (Monobit)',
                'Frequency (Block)',
                'Runs',
                'Longest Run',
                'Rank',
                'Spectral (DFT)',
                'Non-overlapping Template Matching',
                'Overlapping Template Matching',
                'Maurer\'s Universal',
                'Linear Complexity',
                'Serial',
                'Approximate Entropy',
                'Cumulative Sums'
            ]
        }
    
    @staticmethod
    def create_practrand_input(binary_file):
        """
        Create PractRand-compatible input file.
        
        PractRand can read binary files directly.
        Typically tests gigabytes of data.
        """
        if not os.path.exists(binary_file):
            raise FileNotFoundError(f"Binary file not found: {binary_file}")
        
        file_size_mb = os.path.getsize(binary_file) / (1024 * 1024)
        
        return {
            'file': binary_file,
            'file_size_mb': file_size_mb,
            'command': f'RNG_test stdin64 < {binary_file}',
            'sufficient_for_practrand': file_size_mb >= 0.5,
            'recommended_size_mb': 100,
            'notes': 'PractRand progressively detects weaknesses as data increases'
        }
    
    @staticmethod
    def create_dieharder_input(binary_file):
        """
        Create Dieharder-compatible input file.
        
        Dieharder input format:
        - Binary data in any format
        - Can test from 0.5 MB to several GB
        """
        if not os.path.exists(binary_file):
            raise FileNotFoundError(f"Binary file not found: {binary_file}")
        
        file_size_mb = os.path.getsize(binary_file) / (1024 * 1024)
        
        return {
            'file': binary_file,
            'file_size_mb': file_size_mb,
            'command': f'dieharder -a -g 201 -f {binary_file}',
            'sufficient_for_dieharder': file_size_mb >= 0.5,
            'recommended_size_mb': 10,
            'test_battery': [
                'Birthdays',
                'OPSO (Overlapping Pairs)',
                'Runs',
                'Craps',
                'Parking Lot',
                'Minimum Distance',
                'Random Spheres',
                'SQUEeZe',
                '3D Spheres',
                'Count the 1s (stream)',
                'Count the 1s (byte)',
                'Parking Lot',
                '2D Circle'
            ]
        }
