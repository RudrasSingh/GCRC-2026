"""
ACADEMIC EVALUATION PIPELINE - QUICK START

This module provides a complete, publication-grade cryptographic evaluation system
for the GCRC (DNA-based) cipher.

COMPONENTS:
============

1. academic_evaluation.py
   ↳ Main orchestrator - runs complete evaluation pipeline
   ↳ Phases: datasets → NIST tests → entropy → avalanche → differential → comparisons

2. quick_eval.py  
   ↳ Command-line interface
   ↳ Modes: --fast (2-5 min), default (15-25 min), --thorough (40-60 min)

3. academic_report_gen.py
   ↳ Generates publication-ready HTML/JSON/Markdown reports

4. analysis/nist_sp800_22.py
   ↳ Complete NIST SP 800-22 test suite (8 core tests)

5. analysis/cipher_comparison.py
   ↳ Comparative benchmarking with AES-256 and Triple DES

6. analysis/dataset_generator.py
   ↳ Creates binary files for NIST STS, PractRand, Dieharder

7. analysis/differential_analysis_enhanced.py
   ↳ Differential cryptanalysis and linear analysis

8. EVALUATION_PIPELINE_GUIDE.md
   ↳ Comprehensive implementation guide

9. EXTERNAL_TOOLS_GUIDE.md
   ↳ Setup and execution for NIST STS, PractRand, Dieharder


QUICK START:
============

# Method 1: Command line (recommended for first run)
$ python quick_eval.py
$ python quick_eval.py --thorough

# Method 2: Direct Python usage
from academic_evaluation import AcademicCryptoEvaluator

evaluator = AcademicCryptoEvaluator()
report = evaluator.run_full_evaluation(num_samples=5000, nist_samples=100000)

# Method 3: Run individual phases
evaluator.generate_datasets(num_samples=5000)
evaluator.run_nist_sts_tests(num_samples=100000)
evaluator.analyze_entropy(num_samples=5000)
evaluator.analyze_avalanche_effect(num_tests=1000)
evaluator.run_differential_analysis()
evaluator.compare_with_standards()


EVALUATION TESTS:
=================

NIST SP 800-22:
  ✓ Frequency (Monobit) Test
  ✓ Frequency (Block) Test  
  ✓ Runs Test
  ✓ Longest Run of Ones Test
  ✓ Rank Test (Linear Independence)
  ✓ Spectral (DFT) Test
  ✓ Approximate Entropy Test
  ✓ Cumulative Sums Test

Entropy Analysis:
  ✓ Shannon Entropy (bits/byte)
  ✓ Min-Entropy
  ✓ Byte distribution uniformity
  ✓ Chi-square tests
  ✓ Serial correlation

Avalanche Effect:
  ✓ Single-bit input sensitivity
  ✓ Diffusion metrics
  ✓ Statistical analysis

Differential Cryptanalysis:
  ✓ Input/output difference propagation
  ✓ Differential characteristics
  ✓ Linear approximations
  ✓ Key schedule analysis

Comparative Benchmarks:
  ✓ GCRC vs AES-256 performance
  ✓ GCRC vs Triple DES performance
  ✓ Statistical properties comparison
  ✓ Key sensitivity comparison


EXPECTED RESULTS:
=================

Publication-Quality Results:
  • NIST Pass Rate: ≥ 95%
  • Shannon Entropy: ≥ 7.99 bits/byte
  • Avalanche Effect: 0.48-0.52 (ideal: 0.50)
  • Differential Characteristics: minimal high-probability paths
  • Performance: competitive with AES-256


OUTPUT FILES:
=============

evaluation_results/
├── complete_evaluation_results_TIMESTAMP.json
│   ↳ All raw metrics in machine-readable format
│
├── academic_evaluation_report_TIMESTAMP.json
│   ↳ Structured report with metadata
│
├── evaluation_report.html
│   ↳ Publication-ready visualization (open in browser)
│
├── evaluation_report.md
│   ↳ Markdown report for documentation
│
├── gcrc_random_ciphertexts_TIMESTAMP.bin
│   ↳ Binary file for NIST STS (1M+ bits)
│   ↳ Binary file for PractRand testing
│   ↳ Binary file for Dieharder testing
│
├── gcrc_structured_ciphertexts_TIMESTAMP.bin
│   ↳ Edge-case testing file
│
└── gcrc_datasets_metadata_TIMESTAMP.json
    ↳ Dataset generation parameters


NEXT STEPS:
===========

1. VIEW RESULTS
   Open: evaluation_results/evaluation_report.html

2. EXTERNAL VALIDATION
   NIST STS:  ./assess 1000000 < gcrc_random_ciphertexts_*.bin
   PractRand: ./RNG_test stdin64 < gcrc_random_ciphertexts_*.bin
   Dieharder: dieharder -a -g 201 -f gcrc_random_ciphertexts_*.bin

3. PUBLICATION
   Use HTML/JSON results as basis for academic paper
   Include binary validation with external tools
   Compare metrics with published cipher standards


SYSTEM REQUIREMENTS:
====================

Python: 3.8+
RAM: 2GB+ (8GB+ for thorough evaluation)
Disk: 500MB+ for datasets and results
Time: 20-60 minutes depending on mode


KEY METRICS FOR PUBLICATION:
============================

Include in academic paper:

Table 1: NIST SP 800-22 Results
  ├─ Test Name
  ├─ P-value
  ├─ Pass/Fail
  └─ Compare with reference values

Table 2: Entropy Analysis  
  ├─ Shannon Entropy (bits/byte)
  ├─ Min-Entropy
  ├─ Efficiency Percentage
  └─ Chi-square value

Table 3: Avalanche Effect
  ├─ Mean avalanche
  ├─ Standard deviation
  ├─ Min/Max values
  └─ Distribution quartiles

Table 4: Performance Comparison
  ├─ GCRC throughput (MB/s)
  ├─ AES-256 throughput
  ├─ Triple DES throughput
  └─ Relative performance

Figure 1: P-value Distribution (histogram)
Figure 2: Avalanche Distribution (box plot)
Figure 3: Performance Comparison (bar chart)
Figure 4: Entropy Distribution (histogram)


INTERPRETATION GUIDE:
=====================

Pass Rate:
  ✅ ≥ 95%     → Excellent (publication-ready)
  ⚠️  85-95%    → Good (minor improvements suggested)
  ⚠️  70-85%    → Acceptable (needs investigation)
  ❌ < 70%     → Problematic (redesign needed)

Entropy:
  ✅ > 7.99    → Excellent
  ✅ 7.95-7.99 → Very Good
  ⚠️  7.90-7.95 → Good
  ⚠️  < 7.90   → Needs improvement

Avalanche:
  ✅ 0.48-0.52 → Excellent
  ✅ 0.45-0.55 → Very Good
  ⚠️  0.40-0.60 → Acceptable
  ❌ Outside   → Poor


TROUBLESHOOTING:
================

Issue: "ModuleNotFoundError: No module named 'Crypto'"
Solution: pip install pycryptodome

Issue: "Insufficient data for NIST tests"
Solution: python quick_eval.py --thorough (generates more data)

Issue: "MemoryError"
Solution: python quick_eval.py --fast (uses fewer samples)

Issue: "GCRC encryption failed"
Solution: Verify cipher key format (should be 32-char hex string)

See EVALUATION_PIPELINE_GUIDE.md for detailed troubleshooting.


REFERENCES:
===========

Standards:
  • NIST SP 800-22 Rev 1a: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
  • AES (Rijndael): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
  • Triple DES: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-67r2.pdf

External Tools:
  • NIST STS: https://csrc.nist.gov/projects/random-bit-generation/
  • PractRand: http://pracrand.sourceforge.net/
  • Dieharder: https://webhome.phy.duke.edu/~rgb/General/dieharder.php

Academic Papers:
  • Shannon, C. (1949). "Communication Theory of Secrecy Systems"
  • FIPS 140-2 Validation Program
  • Common Cryptographic Testing Standards


DOCUMENTATION:
===============

1. EVALUATION_PIPELINE_GUIDE.md
   → Complete implementation guide
   → Installation, usage, interpretation
   → Publication workflow

2. EXTERNAL_TOOLS_GUIDE.md  
   → NIST STS, PractRand, Dieharder setup
   → Step-by-step instructions
   → Results interpretation

3. This file (README)
   → Quick reference
   → Getting started
   → Quick links


SUPPORT & CONTACT:
==================

For technical issues:
1. Check troubleshooting section in EVALUATION_PIPELINE_GUIDE.md
2. Review pipeline output for detailed error messages
3. Consult NIST documentation for test interpretation
4. Validate with external tools for independent verification


Version: 1.0
Last Updated: 2026-05-13
Status: Production Ready ✓

═══════════════════════════════════════════════════════════════════════════

TO GET STARTED:

  python quick_eval.py           # Run default evaluation
  python quick_eval.py --help-full  # See detailed options
  python quick_eval.py --thorough   # Publication-quality evaluation

═══════════════════════════════════════════════════════════════════════════
"""

# This file serves as comprehensive documentation.
# The actual pipeline is implemented in:
# - academic_evaluation.py (main orchestrator)
# - quick_eval.py (CLI interface)
# - academic_report_gen.py (report generation)
# - analysis/ (individual test modules)

if __name__ == "__main__":
    print(__doc__)
