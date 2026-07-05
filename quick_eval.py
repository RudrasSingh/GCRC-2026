"""
Quick-Start Evaluation Script

Run the complete academic evaluation pipeline with a single command.

Usage:
    python quick_eval.py                    # Run with defaults
    python quick_eval.py --fast             # Quick evaluation (fewer samples)
    python quick_eval.py --thorough         # Thorough evaluation (more samples)
    python quick_eval.py --compare          # Include AES/DES comparison
    python quick_eval.py --samples 5000     # Custom sample count
"""

import argparse
import sys
import time
from pathlib import Path

# Import evaluation framework
from academic_evaluation import AcademicCryptoEvaluator
from academic_report_gen import AcademicReportGenerator, export_to_markdown


def print_banner():
    """Print welcome banner"""
    try:
        print("""
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║        ACADEMIC CRYPTOGRAPHIC EVALUATION PIPELINE                     ║
    ║                                                                        ║
    ║        DNA-based GCRC Cipher Cryptanalysis Suite                      ║
    ║        Evaluation Framework v1.0                                      ║
    ║                                                                        ║
    ║        Standards: NIST SP 800-22, Industry Benchmarks                 ║
    ║                                                                        ║
    ╚════════════════════════════════════════════════════════════════════════╝
    """)
    except:
        # Fallback to ASCII if Unicode fails
        print("""
    ========================================================================
    
        ACADEMIC CRYPTOGRAPHIC EVALUATION PIPELINE
        
        DNA-based GCRC Cipher Cryptanalysis Suite
        Evaluation Framework v1.0
        
        Standards: NIST SP 800-22, Industry Benchmarks
    
    ========================================================================
    """)


def print_help_text():
    """Print detailed help information"""
    try:
        help_text = """
    
╔════════════════════════════════════════════════════════════════════════╗
║                         EVALUATION MODES                              ║
╚════════════════════════════════════════════════════════════════════════╝

QUICK EVALUATION (--fast)
  • 1,000 ciphertext samples for datasets
  • 50,000 bits for NIST testing
  • 100 avalanche tests
  • ~2-5 minutes
  • Good for development/debugging

DEFAULT EVALUATION
  • 5,000 ciphertext samples for datasets
  • 100,000 bits for NIST testing
  • 500 avalanche tests
  • ~10-20 minutes
  • Good for preliminary assessment

THOROUGH EVALUATION (--thorough)
  • 10,000+ ciphertext samples for datasets
  • 1,000,000 bits for NIST testing
  • 1,000+ avalanche tests
  • ~30-60 minutes
  • PUBLICATION QUALITY


╔════════════════════════════════════════════════════════════════════════╗
║                      WHAT GETS TESTED                                 ║
╚════════════════════════════════════════════════════════════════════════╝

PHASE 1: DATASET GENERATION
  [+] Random plaintext ciphertexts
  [+] Structured plaintext ciphertexts
  [+] Binary files for external tools
  
PHASE 2: NIST SP 800-22 TESTS
  [+] Frequency (Monobit) Test
  [+] Frequency (Block) Test
  [+] Runs Test
  [+] Longest Run of Ones Test
  [+] Rank Test (Linear Independence)
  [+] Spectral (DFT) Test
  [+] Approximate Entropy Test
  [+] Cumulative Sums Test

PHASE 3: ENTROPY ANALYSIS
  [+] Shannon Entropy (bits/byte)
  [+] Min-Entropy
  [+] Byte distribution uniformity
  [+] Chi-square tests

PHASE 4: AVALANCHE EFFECT
  [+] Single-bit input changes
  [+] Propagation statistics

PHASE 5: DIFFERENTIAL CRYPTANALYSIS
  [+] Input/output difference propagation
  [+] Linear approximations

PHASE 6: COMPARATIVE BENCHMARKING
  [+] Performance vs AES-256
  [+] Performance vs Triple DES


OUTPUT FILES:
  - evaluation_results/ directory
  - HTML report (publication-ready)
  - JSON results (machine-readable)
  - Binary datasets for external tools


INTERPRETING RESULTS:

NIST STS RESULTS
  [PASS] Pass Rate >= 95%
  [GOOD] Pass Rate >= 85%
  [WARN] Pass Rate >= 70%
  [FAIL] Pass Rate < 70%

ENTROPY (bits/byte)
  [PASS] > 7.99
  [GOOD] > 7.95
  [WARN] > 7.90
  [FAIL] <= 7.90

AVALANCHE EFFECT
  [PASS] 0.48 - 0.52 (ideal 50%)
  [GOOD] 0.45 - 0.55
  [WARN] 0.40 - 0.60
"""
        print(help_text)
    except:
        # Fallback to plain ASCII
        print("""
========================================================================
                    ACADEMIC EVALUATION PIPELINE
========================================================================

QUICK EVALUATION (--fast)
  - 1,000 ciphertext samples
  - 50,000 NIST bits
  - ~2-5 minutes

DEFAULT EVALUATION  
  - 5,000 ciphertext samples
  - 100,000 NIST bits
  - ~10-20 minutes

THOROUGH EVALUATION (--thorough)
  - 10,000 ciphertext samples
  - 1,000,000 NIST bits
  - ~30-60 minutes (PUBLICATION QUALITY)

PHASES TESTED:
  1. Dataset Generation
  2. NIST SP 800-22 Tests (8 statistical tests)
  3. Entropy Analysis (Shannon, Min-entropy, Chi-square)
  4. Avalanche Effect (diffusion analysis)
  5. Differential Cryptanalysis
  6. Comparative Benchmarking (vs AES-256, 3DES)

OUTPUT FILES:
  - evaluation_results/ directory
  - HTML report (publication-ready)
  - JSON results (machine-readable)
  - Binary datasets for external tools
""")


def run_evaluation(args):
    """Execute the evaluation pipeline"""
    
    # Determine evaluation parameters based on mode
    if args.fast:
        num_samples = 1000
        nist_samples = 50000
        print("Mode: QUICK EVALUATION (--fast)")
    elif args.thorough:
        num_samples = 10000
        nist_samples = 1000000
        print("Mode: THOROUGH EVALUATION (--thorough)")
    else:
        num_samples = args.samples if args.samples else 5000
        nist_samples = args.nist_samples if args.nist_samples else 100000
        print("Mode: DEFAULT EVALUATION")
    
    print(f"Parameters: {num_samples} samples, {nist_samples} NIST bits")
    print()
    
    # Create evaluator
    evaluator = AcademicCryptoEvaluator(
        output_dir=args.output,
        cipher_key=args.key
    )
    
    # Run full evaluation
    start_time = time.time()
    
    try:
        report = evaluator.run_full_evaluation(
            num_samples=num_samples,
            nist_samples=nist_samples
        )
        
        elapsed = time.time() - start_time
        
        # Generate HTML report
        if report:
            print("\nGenerating publication-ready report...")
            report_gen = AcademicReportGenerator(output_dir=args.output)
            html_file = report_gen.generate_html_report(evaluator.results)
            print(f"HTML Report: {html_file}")
            
            # Also export to markdown
            md_file = export_to_markdown(
                evaluator.results,
                f'{args.output}/evaluation_report.md'
            )
            print(f"Markdown Report: {md_file}")
        
        print(f"\n{'='*70}")
        print(f"EVALUATION COMPLETED SUCCESSFULLY")
        print(f"{'='*70}")
        print(f"Total time: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
        print(f"Results saved to: {args.output}/")
        print(f"\nNext steps:")
        print(f"1. Review the HTML report: open {args.output}/evaluation_report.html")
        print(f"2. Validate with external tools (NIST STS, PractRand, Dieharder)")
        print(f"3. Use binary datasets for additional analysis")
        print()
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nEvaluation interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n\nError during evaluation: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description='Academic Cryptographic Evaluation Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Use --help-full for detailed information'
    )
    
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--fast', action='store_true',
                           help='Quick evaluation (1000 samples, ~2-5 minutes)')
    mode_group.add_argument('--thorough', action='store_true',
                           help='Thorough evaluation (10000+ samples, ~30-60 minutes)')
    
    parser.add_argument('--samples', type=int, default=None,
                       help='Custom number of samples (overrides mode)')
    parser.add_argument('--nist-samples', type=int, default=None,
                       help='Custom number of NIST test bits')
    
    parser.add_argument('--output', type=str, default='evaluation_results',
                       help='Output directory (default: evaluation_results)')
    parser.add_argument('--key', type=str, default='academic-evaluation-key',
                       help='GCRC cipher key')
    
    parser.add_argument('--help-full', action='store_true',
                       help='Display detailed help information')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Show full help if requested
    if args.help_full:
        print_help_text()
        return 0
    
    # Run evaluation
    return run_evaluation(args)


if __name__ == "__main__":
    sys.exit(main())
