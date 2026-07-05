"""
QUICK DNA-GCRC CIPHER EVALUATION
Run this to test your cipher with proper DNA-native metrics
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from dna_evaluation_suite import DNACryptoEvaluator
from cipher.gcrc_cipher import GCRC


def main():
    print("""
╔════════════════════════════════════════════════════════════════╗
║          DNA-GCRC CIPHER EVALUATION (DNA-Native)              ║
║                                                                ║
║  Using proper DNA base metrics instead of byte-based tests    ║
║  This matches your existing crypto_tests.py methodology       ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Create evaluator
    evaluator = DNACryptoEvaluator("evaluation_results")
    
    # Create cipher
    cipher = GCRC("test-key")
    
    # Run evaluation
    print("\nStarting DNA-native evaluation...\n")
    
    results = evaluator.evaluate_dna_cipher(
        "DNA-GCRC",
        cipher,
        num_samples=1000,      # Test with 1000 samples
        num_tests=500          # 500 tests per metric
    )
    
    # Save results
    evaluator.save_results()
    
    # Print report
    print("\n" + evaluator.generate_report())
    
    print("""
╔════════════════════════════════════════════════════════════════╗
║                    EVALUATION COMPLETE                        ║
╚════════════════════════════════════════════════════════════════╝

Files saved to: evaluation_results/
  ✓ dna_evaluation_*.json       (raw metrics)
  ✓ dna_evaluation_*.txt        (report)

Expected Results:
  ✓ Avalanche:          ~75% ± 10%   (DNA bases)
  ✓ NPCR:               ~75%         (base change rate)
  ✓ Base Distribution:  PASS         (χ² < 7.815)
  ✓ Bit Entropy:        > 0.99       (close to 1.0)

If you see these ranges, your cipher is working correctly!

Compare with your crypto_tests.py results to verify.
    """)


if __name__ == "__main__":
    main()
